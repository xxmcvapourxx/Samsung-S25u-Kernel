// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/tick.h>
#include "walt.h"
#include "trace.h"
#include <trace/events/power.h>

bool smart_freq_init_done;
char reason_dump[1024];
static DEFINE_MUTEX(freq_reason_mutex);

int sched_smart_freq_legacy_dump_handler(struct ctl_table *table, int write,
					 void __user *buffer, size_t *lenp,
					 loff_t *ppos)
{
	int ret = -EINVAL, pos = 0, i, j;

	if (!smart_freq_init_done)
		return -EINVAL;

	mutex_lock(&freq_reason_mutex);
	for (j = 0; j < num_sched_clusters; j++) {
		for (i = 0; i < LEGACY_SMART_FREQ; i++) {
			pos += snprintf(reason_dump + pos, 50, "%d:%d:%lu:%llu:%d\n", j, i,
			       default_freq_config[j].legacy_reason_config[i].freq_allowed,
			       default_freq_config[j].legacy_reason_config[i].hyst_ns,
			       !!(default_freq_config[j].smart_freq_participation_mask &
				  BIT(i)));
		}
	}

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	mutex_unlock(&freq_reason_mutex);

	return ret;
}

int sched_smart_freq_ipc_dump_handler(struct ctl_table *table, int write,
					 void __user *buffer, size_t *lenp,
					 loff_t *ppos)
{
	int ret = -EINVAL, pos = 0, i, j;

	if (!smart_freq_init_done)
		return -EINVAL;

	mutex_lock(&freq_reason_mutex);

	for (j = 0; j < num_sched_clusters; j++) {
		for (i = 0; i < SMART_FMAX_IPC_MAX; i++) {
			pos += snprintf(reason_dump + pos, 50, "%d:%d:%lu:%lu:%llu:%d\n", j, i,
			       default_freq_config[j].ipc_reason_config[i].ipc,
			       default_freq_config[j].ipc_reason_config[i].freq_allowed,
			       default_freq_config[j].ipc_reason_config[i].hyst_ns,
			       !!(default_freq_config[j].smart_freq_ipc_participation_mask &
					BIT(i)));
		}
	}

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	mutex_unlock(&freq_reason_mutex);

	return ret;
}

int sched_smart_freq_ipc_handler(struct ctl_table *table, int write,
				      void __user *buffer, size_t *lenp,
				      loff_t *ppos)
{
	int ret;
	int cluster_id = -1;
	unsigned long no_reason_freq;
	int i;
	unsigned int *data = (unsigned int *)table->data;
	int val[SMART_FMAX_IPC_MAX];
	struct ctl_table tmp = {
		.data	= &val,
		.maxlen	= sizeof(int) * SMART_FMAX_IPC_MAX,
		.mode	= table->mode,
	};

	if (!smart_freq_init_done)
		return -EINVAL;

	mutex_lock(&freq_reason_mutex);

	if (!write) {
		tmp.data = table->data;
		ret = proc_dointvec(&tmp, write, buffer, lenp, ppos);
		goto unlock;
	}

	ret = proc_dointvec(&tmp, write, buffer, lenp, ppos);
	if (ret)
		goto unlock;

	ret = -EINVAL;

	if (data == &sysctl_ipc_freq_levels_cluster0[0])
		cluster_id = 0;
	if (data == &sysctl_ipc_freq_levels_cluster1[0])
		cluster_id = 1;
	if (data == &sysctl_ipc_freq_levels_cluster2[0])
		cluster_id = 2;
	if (data == &sysctl_ipc_freq_levels_cluster3[0])
		cluster_id = 3;
	if (cluster_id == -1)
		goto unlock;

	if (val[0] < 0)
		goto unlock;

	no_reason_freq = val[0];

	/* Make sure all reasons freq are larger than NO_REASON */
	/* IPC/freq should be in increasing order */
	for (i = 1; i < SMART_FMAX_IPC_MAX; i++) {
		if (val[i] < val[i-1])
			goto unlock;
	}

	default_freq_config[cluster_id].legacy_reason_config[NO_REASON_SMART_FREQ].freq_allowed =
		no_reason_freq;

	for (i = 0; i < SMART_FMAX_IPC_MAX; i++) {
		default_freq_config[cluster_id].ipc_reason_config[i].freq_allowed = val[i];
		data[i] = val[i];
	}
	ret = 0;

unlock:
	mutex_unlock(&freq_reason_mutex);
	return ret;
}

/* return highest ipc of the cluster */
unsigned int get_cluster_ipc_level_freq(int curr_cpu, u64 time)
{
	int cpu, winning_cpu, cpu_ipc_level = 0, index = 0;
	struct walt_sched_cluster *cluster = cpu_cluster(curr_cpu);
	struct smart_freq_cluster_info *smart_freq_info = cluster->smart_freq_info;

	if (!smart_freq_init_done)
		return 0;

	for_each_cpu(cpu, &cluster->cpus) {
		cpu_ipc_level = per_cpu(ipc_level, cpu);

		if ((time - per_cpu(last_ipc_update, cpu)) > 7999999ULL) {
			cpu_ipc_level = 0;
			per_cpu(tickless_mode, cpu) = true;
		} else {
			per_cpu(tickless_mode, cpu) = false;
		}


		if (cpu_ipc_level >= index) {
			winning_cpu = cpu;
			index = cpu_ipc_level;
		}
	}

	smart_freq_info->cluster_ipc_level = index;

	trace_ipc_freq(cluster->id, winning_cpu, index,
		smart_freq_info->ipc_reason_config[index].freq_allowed,
		time, per_cpu(ipc_deactivate_ns, winning_cpu), curr_cpu,
		per_cpu(ipc_cnt, curr_cpu));

	return smart_freq_info->ipc_reason_config[index].freq_allowed;
}

static inline bool has_internal_freq_limit_changed(struct walt_sched_cluster *cluster)
{
	unsigned int internal_freq, ipc_freq;
	int i;
	struct smart_freq_cluster_info *smci = cluster->smart_freq_info;

	internal_freq = cluster->walt_internal_freq_limit;
	cluster->walt_internal_freq_limit = cluster->max_freq;

	for (i = 0; i < MAX_FREQ_CAP; i++)
		cluster->walt_internal_freq_limit = min(freq_cap[i][cluster->id],
				     cluster->walt_internal_freq_limit);

	ipc_freq = smci->ipc_reason_config[smci->cluster_ipc_level].freq_allowed;
	cluster->walt_internal_freq_limit = max(ipc_freq,
			     cluster->walt_internal_freq_limit);

	return cluster->walt_internal_freq_limit != internal_freq;
}

void update_smart_freq_capacities_one_cluster(struct walt_sched_cluster *cluster)
{
	int cpu;

	if (!smart_freq_init_done)
		return;

	if (has_internal_freq_limit_changed(cluster)) {
		for_each_cpu(cpu, &cluster->cpus)
			update_cpu_capacity_helper(cpu);
	}
}

void update_smart_freq_capacities(void)
{
	struct walt_sched_cluster *cluster;

	if (!smart_freq_init_done)
		return;

	for_each_sched_cluster(cluster)
		update_smart_freq_capacities_one_cluster(cluster);
}

/*
 *  Update the active smart freq reason for the cluster.
 */
static void smart_freq_update_one_cluster(struct walt_sched_cluster *cluster,
			uint32_t current_reasons, u64 wallclock, int nr_big, u32 wakeup_ctr_sum)
{
	uint32_t current_reason, cluster_active_reason;
	struct smart_freq_cluster_info *smart_freq_info = cluster->smart_freq_info;
	unsigned long max_cap =
		smart_freq_info->legacy_reason_config[NO_REASON_SMART_FREQ].freq_allowed;
	int max_reason, i;
	unsigned long old_freq_cap = freq_cap[SMART_FREQ][cluster->id];
	struct rq *rq;
	char smart_freq[25] = {0};
	char smart_freq_reason[25] = {0};

	for (i = 0; i < LEGACY_SMART_FREQ; i++) {
		current_reason = current_reasons & BIT(i);
		cluster_active_reason = smart_freq_info->cluster_active_reason & BIT(i);

		if (current_reason) {
			smart_freq_info->legacy_reason_status[i].deactivate_ns = 0;
			smart_freq_info->cluster_active_reason |= BIT(i);

			if (i == TRAILBLAZER_SMART_FREQ)
				trail_active = true;
			else if (i == SUSTAINED_HIGH_UTIL_SMART_FREQ)
				sustain_active = true;

		} else if (cluster_active_reason) {
			if (!smart_freq_info->legacy_reason_status[i].deactivate_ns)
				smart_freq_info->legacy_reason_status[i].deactivate_ns = wallclock;
		}

		if (cluster_active_reason) {
			/*
			 * For reasons with deactivation hysteresis, check here if we have
			 * crossed the hysteresis time and then deactivate the reason.
			 * We are relying on scheduler tick path to call this function
			 * thus deactivation of reason is only at tick
			 * boundary.
			 */
			if (smart_freq_info->legacy_reason_status[i].deactivate_ns) {
				u64 delta = wallclock -
					smart_freq_info->legacy_reason_status[i].deactivate_ns;
				if (delta >= smart_freq_info->legacy_reason_config[i].hyst_ns) {
					smart_freq_info->legacy_reason_status[i].deactivate_ns = 0;
					smart_freq_info->cluster_active_reason &= ~BIT(i);

					if (i == TRAILBLAZER_SMART_FREQ)
						trail_active = false;
					else if (i == SUSTAINED_HIGH_UTIL_SMART_FREQ)
						sustain_active = false;

					continue;
				}
			}
			if (max_cap < smart_freq_info->legacy_reason_config[i].freq_allowed) {
				max_cap = smart_freq_info->legacy_reason_config[i].freq_allowed;
				max_reason = i;
			}
		}
	}

	if (enable_logging) {
		snprintf(smart_freq, sizeof(smart_freq), "smart_fmax_%d", cluster->id);
		trace_clock_set_rate(smart_freq, max_cap, raw_smp_processor_id());

		snprintf(smart_freq_reason, sizeof(smart_freq_reason), "legacy_reason_%d", cluster->id);
		trace_clock_set_rate(smart_freq_reason, max_reason, raw_smp_processor_id());
	}

	trace_sched_freq_uncap(cluster->id, nr_big, wakeup_ctr_sum, current_reasons,
				smart_freq_info->cluster_active_reason, max_cap, max_reason);

	if (old_freq_cap == max_cap)
		return;

	freq_cap[SMART_FREQ][cluster->id] = max_cap;

	rq = cpu_rq(cpumask_first(&cluster->cpus));
	/*
	 * cpufreq smart freq doesn't call get_util for the cpu, hence
	 * invoking callback without rq lock is safe.
	 */
	waltgov_run_callback(rq, WALT_CPUFREQ_SMART_FREQ_BIT);
}

#define UNCAP_THRES		300000000
#define UTIL_THRESHOLD		90
static bool thres_based_uncap(u64 window_start, struct walt_sched_cluster *cluster)
{
	int cpu;
	bool cluster_high_load = false, sustained_load = false;
	unsigned long freq_capacity, tgt_cap;
	unsigned long tgt_freq =
		cluster->smart_freq_info->legacy_reason_config[NO_REASON_SMART_FREQ].freq_allowed;
	struct walt_rq *wrq;

	freq_capacity = arch_scale_cpu_capacity(cpumask_first(&cluster->cpus));
	tgt_cap = mult_frac(freq_capacity, tgt_freq, cluster->max_possible_freq);

	for_each_cpu(cpu, &cluster->cpus) {
		wrq = &per_cpu(walt_rq, cpu);
		if (wrq->util >= mult_frac(tgt_cap, UTIL_THRESHOLD, 100)) {
			cluster_high_load = true;
			if (!cluster->found_ts)
				cluster->found_ts = window_start;
			else if ((window_start - cluster->found_ts) >= UNCAP_THRES)
				sustained_load = true;

			break;
		}
	}
	if (!cluster_high_load)
		cluster->found_ts = 0;

	return sustained_load;
}

unsigned int big_task_cnt = 6;
#define WAKEUP_CNT		100
/*
 * reason is a two part bitmap
 * 15 - 0 : reason type
 * 31 - 16: changed state of reason
 * this will help to pass multiple reasons at once and avoid multiple calls.
 */
/*
 * This will be called from irq work path only
 */
void smart_freq_update_reason_common(u64 wallclock, int nr_big, u32 wakeup_ctr_sum)
{
	struct walt_sched_cluster *cluster;
	bool current_state;
	uint32_t cluster_reasons;
	int i;
	int cluster_active_reason;
	uint32_t cluster_participation_mask;
	bool sustained_load = false;

	if (!smart_freq_init_done)
		return;

	for_each_sched_cluster(cluster)
		sustained_load |= thres_based_uncap(wallclock, cluster);

	for_each_sched_cluster(cluster) {
		cluster_reasons = 0;
		i = cluster->id;
		cluster_participation_mask =
			cluster->smart_freq_info->smart_freq_participation_mask;
		/*
		 *  NO_REASON
		 */
		if (cluster_participation_mask & BIT(NO_REASON_SMART_FREQ))
			cluster_reasons |= BIT(NO_REASON_SMART_FREQ);

		/*
		 * BOOST
		 */
		if (cluster_participation_mask & BIT(BOOST_SMART_FREQ)) {
			current_state = is_storage_boost() || is_full_throttle_boost();
			if (current_state)
				cluster_reasons |= BIT(BOOST_SMART_FREQ);
		}

		/*
		 * TRAILBLAZER
		 */
		if (cluster_participation_mask & BIT(TRAILBLAZER_SMART_FREQ)) {
			current_state = trailblazer_state;
			if (current_state)
				cluster_reasons |= BIT(TRAILBLAZER_SMART_FREQ);
		}

		/*
		 * SBT
		 */
		if (cluster_participation_mask & BIT(SBT_SMART_FREQ)) {
			current_state = prev_is_sbt;
			if (current_state)
				cluster_reasons |= BIT(SBT_SMART_FREQ);
		}

		/*
		 * BIG_TASKCNT
		 */
		if (cluster_participation_mask & BIT(BIG_TASKCNT_SMART_FREQ)) {
			current_state = (nr_big >= big_task_cnt) &&
						(wakeup_ctr_sum < WAKEUP_CNT);
			if (current_state)
				cluster_reasons |= BIT(BIG_TASKCNT_SMART_FREQ);
		}

		/*
		 * SUSTAINED_HIGH_UTIL
		 */
		if (cluster_participation_mask & BIT(SUSTAINED_HIGH_UTIL_SMART_FREQ)) {
			current_state = sustained_load;
			if (current_state)
				cluster_reasons |= BIT(SUSTAINED_HIGH_UTIL_SMART_FREQ);
		}

		/*
		 * PIPELINE_60FPS_OR_LESSER
		 */
		if (cluster_participation_mask &
				BIT(PIPELINE_60FPS_OR_LESSER_SMART_FREQ)) {
			current_state = pipeline_in_progress() &&
						sched_ravg_window >= SCHED_RAVG_16MS_WINDOW;
			if (current_state)
				cluster_reasons |=
					BIT(PIPELINE_60FPS_OR_LESSER_SMART_FREQ);
		}

		/*
		 * PIPELINE_90FPS
		 */
		if (cluster_participation_mask &
				BIT(PIPELINE_90FPS_SMART_FREQ)) {
			current_state = pipeline_in_progress() &&
						sched_ravg_window == SCHED_RAVG_12MS_WINDOW;
			if (current_state)
				cluster_reasons |=
					BIT(PIPELINE_90FPS_SMART_FREQ);
		}

		/*
		 * PIPELINE_120FPS_OR_GREATER
		 */
		if (cluster_participation_mask &
				BIT(PIPELINE_120FPS_OR_GREATER_SMART_FREQ)) {
			current_state = pipeline_in_progress() &&
						sched_ravg_window == SCHED_RAVG_8MS_WINDOW;
			if (current_state)
				cluster_reasons |=
					BIT(PIPELINE_120FPS_OR_GREATER_SMART_FREQ);
		}

		/*
		 * THERMAL_ROTATION
		 */
		if (cluster_participation_mask & BIT(THERMAL_ROTATION_SMART_FREQ)) {
			current_state = (oscillate_cpu != -1);
			if (current_state)
				cluster_reasons |= BIT(THERMAL_ROTATION_SMART_FREQ);
		}

		cluster_active_reason = cluster->smart_freq_info->cluster_active_reason;
		/* update the reasons for all the clusters */
		if (cluster_reasons || cluster_active_reason)
			smart_freq_update_one_cluster(cluster, cluster_reasons, wallclock,
						      nr_big, wakeup_ctr_sum);
	}
}

/* Common config for 4 cluster system */
struct smart_freq_cluster_info default_freq_config[MAX_CLUSTERS];

void smart_freq_init(const char *name)
{
	struct walt_sched_cluster *cluster;
	int i = 0, j;

	for_each_sched_cluster(cluster) {
		cluster->smart_freq_info = &default_freq_config[i];
		cluster->smart_freq_info->smart_freq_participation_mask = BIT(NO_REASON_SMART_FREQ);
		cluster->smart_freq_info->cluster_active_reason = 0;
		cluster->smart_freq_info->min_cycles = 100;
		cluster->smart_freq_info->smart_freq_ipc_participation_mask = 0;
		freq_cap[SMART_FREQ][cluster->id] = FREQ_QOS_MAX_DEFAULT_VALUE;

		memset(cluster->smart_freq_info->legacy_reason_status, 0,
		       sizeof(struct smart_freq_legacy_reason_status) *
		       LEGACY_SMART_FREQ);
		memset(cluster->smart_freq_info->legacy_reason_config, 0,
		       sizeof(struct smart_freq_legacy_reason_config) *
		       LEGACY_SMART_FREQ);
		memset(cluster->smart_freq_info->ipc_reason_config, 0,
		       sizeof(struct smart_freq_ipc_reason_config) *
		       SMART_FMAX_IPC_MAX);

		for (j = 0; j < LEGACY_SMART_FREQ; j++) {
			cluster->smart_freq_info->legacy_reason_config[j].freq_allowed =
				FREQ_QOS_MAX_DEFAULT_VALUE;
		}
		for (j = 0; j < SMART_FMAX_IPC_MAX; j++) {
			cluster->smart_freq_info->ipc_reason_config[j].freq_allowed =
				FREQ_QOS_MAX_DEFAULT_VALUE;
			sysctl_ipc_freq_levels_cluster0[j] = FREQ_QOS_MAX_DEFAULT_VALUE;
			sysctl_ipc_freq_levels_cluster1[j] = FREQ_QOS_MAX_DEFAULT_VALUE;
			sysctl_ipc_freq_levels_cluster2[j] = FREQ_QOS_MAX_DEFAULT_VALUE;
			sysctl_ipc_freq_levels_cluster3[j] = FREQ_QOS_MAX_DEFAULT_VALUE;
		}

		i++;
	}

	if (!strcmp(name, "SUN")) {
		for_each_sched_cluster(cluster) {
			if (cluster->id == 0) {
				/* Legacy */
				cluster->smart_freq_info->legacy_reason_config[0].freq_allowed =
					2400000;
				cluster->smart_freq_info->legacy_reason_config[2].hyst_ns =
					1000000000;
				cluster->smart_freq_info->legacy_reason_config[3].hyst_ns =
					1000000000;
				cluster->smart_freq_info->legacy_reason_config[4].hyst_ns =
					300000000;
				cluster->smart_freq_info->smart_freq_participation_mask |=
					BIT(BOOST_SMART_FREQ) |
					BIT(SUSTAINED_HIGH_UTIL_SMART_FREQ) |
					BIT(BIG_TASKCNT_SMART_FREQ) |
					BIT(TRAILBLAZER_SMART_FREQ) |
					BIT(SBT_SMART_FREQ) |
					BIT(PIPELINE_60FPS_OR_LESSER_SMART_FREQ) |
					BIT(PIPELINE_90FPS_SMART_FREQ) |
					BIT(PIPELINE_120FPS_OR_GREATER_SMART_FREQ) |
					BIT(THERMAL_ROTATION_SMART_FREQ);

				/* IPC */
				cluster->smart_freq_info->ipc_reason_config[0].ipc = 120;
				cluster->smart_freq_info->ipc_reason_config[1].ipc = 180;
				cluster->smart_freq_info->ipc_reason_config[2].ipc = 220;
				cluster->smart_freq_info->ipc_reason_config[3].ipc = 260;
				cluster->smart_freq_info->ipc_reason_config[4].ipc = 300;
				cluster->smart_freq_info->smart_freq_ipc_participation_mask =
					BIT(IPC_A) | BIT(IPC_B) | BIT(IPC_C) | BIT(IPC_D) |
					BIT(IPC_E);
				cluster->smart_freq_info->min_cycles = 5806080;
			} else if (cluster->id == 1) {
				/* Legacy */
				cluster->smart_freq_info->legacy_reason_config[0].freq_allowed =
					3513600;
				cluster->smart_freq_info->legacy_reason_config[2].hyst_ns =
					1000000000;
				cluster->smart_freq_info->legacy_reason_config[3].hyst_ns =
					1000000000;
				cluster->smart_freq_info->legacy_reason_config[4].hyst_ns =
					300000000;
				cluster->smart_freq_info->smart_freq_participation_mask |=
					BIT(BOOST_SMART_FREQ) |
					BIT(SUSTAINED_HIGH_UTIL_SMART_FREQ) |
					BIT(BIG_TASKCNT_SMART_FREQ) |
					BIT(TRAILBLAZER_SMART_FREQ) |
					BIT(SBT_SMART_FREQ) |
					BIT(PIPELINE_60FPS_OR_LESSER_SMART_FREQ) |
					BIT(PIPELINE_90FPS_SMART_FREQ) |
					BIT(PIPELINE_120FPS_OR_GREATER_SMART_FREQ) |
					BIT(THERMAL_ROTATION_SMART_FREQ);

				/* IPC */
				cluster->smart_freq_info->ipc_reason_config[0].ipc = 220;
				cluster->smart_freq_info->ipc_reason_config[1].ipc = 260;
				cluster->smart_freq_info->ipc_reason_config[2].ipc = 280;
				cluster->smart_freq_info->ipc_reason_config[3].ipc = 320;
				cluster->smart_freq_info->ipc_reason_config[4].ipc = 400;
				cluster->smart_freq_info->smart_freq_ipc_participation_mask =
					BIT(IPC_A) | BIT(IPC_B) | BIT(IPC_C) | BIT(IPC_D) |
					BIT(IPC_E);
				cluster->smart_freq_info->min_cycles = 7004160;
			}
		}
	}
	smart_freq_init_done = true;
	update_smart_freq_capacities();

}
