/*
 * Copyright (c) 2003, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 4851638
 * @key randomness
 * @summary Tests for StrictMath.hypot
 * @library /test/lib
 * @build jdk.test.lib.RandomFactory
 * @build Tests
 * @build FdlibmTranslit
 * @build HypotTests
 * @run main HypotTests
 * @author Joseph D. Darcy
 */
package test.java.lang.StrictMath;

import android.platform.test.annotations.LargeTest;

import java.util.Random;
import org.testng.annotations.Test;

/**
 * The tests in ../Math/HypotTests.java test properties that should hold for any hypot
 * implementation, including the FDLIBM-based one required for StrictMath.hypot.  Therefore, the
 * test cases in ../Math/HypotTests.java are run against both the Math and StrictMath versions of
 * hypot.  The role of this test is to verify that the FDLIBM hypot algorithm is being used by
 * running golden file tests on values that may vary from one conforming hypot implementation to
 * another.
 */

public class HypotTests {

    private HypotTests() {
    }

    /**
     * The hypot implementation is commutative, {@code hypot(a, b) == hypot(b, a)}, and independent
     * of sign, {@code hypot(a, b) == hypot(-a, b) == hypot(a, -b) == hypot(-a, -b)}.
     */
    static void testHypotCase(double input1, double input2, double expected) {
        Tests.test("StrictMath.hypot(double)", input1, input2,
                StrictMath.hypot(input1, input2), expected);

        Tests.test("StrictMath.hypot(double)", input2, input1,
                StrictMath.hypot(input2, input1), expected);

        Tests.test("StrictMath.hypot(double)", -input1, input2,
                StrictMath.hypot(-input1, input2), expected);

        Tests.test("StrictMath.hypot(double)", input2, -input1,
                StrictMath.hypot(input2, -input1), expected);

        Tests.test("StrictMath.hypot(double)", input1, -input2,
                StrictMath.hypot(input1, -input2), expected);

        Tests.test("StrictMath.hypot(double)", -input2, input1,
                StrictMath.hypot(-input2, input1), expected);

        Tests.test("StrictMath.hypot(double)", -input1, -input2,
                StrictMath.hypot(-input1, -input2), expected);

        Tests.test("StrictMath.hypot(double)", -input2, -input1,
                StrictMath.hypot(-input2, -input1), expected);
    }

    @Test
    public void testHypot() {
        double[][] testCases = {
                {0x1.0p0, 0x1.ffffffffffab5p-1, 0x1.6a09e667f39edp0},
                {0x1.0p0, 0x1.ffffffffffffbp0, 0x1.1e3779b97f4a6p1},
                {0x1.0p0, 0x1.7ffffffffffffp1, 0x1.94c583ada5b51p1},
                {0x1.0p0, 0x1.ffffffffffffdp1, 0x1.07e0f66afed06p2},
                {0x1.0p0, 0x1.3fffffffffffdp2, 0x1.465655f122ff3p2},
                {0x1.0p0, 0x1.4p2, 0x1.465655f122ff6p2},
                {0x1.0p0, 0x1.7ffffffffffffp2, 0x1.854bfb363dc38p2},
                {0x1.0p0, 0x1.8p2, 0x1.854bfb363dc39p2},
                {0x1.0p0, 0x1.bfffffffffffep2, 0x1.c48c6001f0abdp2},
                {0x1.0p0, 0x1.fffffffffffffp2, 0x1.01fe03f61badp3},
                {0x1.0p0, 0x1.1fffffffffffap3, 0x1.21c5b70d9f81dp3},
                {0x1.0p0, 0x1.3ffffffffffe5p3, 0x1.419894c2329d5p3},
                {0x1.0p0, 0x1.3ffffffffffe7p3, 0x1.419894c2329d8p3},
                {0x1.0p0, 0x1.5ffffffffff7ep3, 0x1.617398f2aa9c6p3},
                {0x1.0p0, 0x1.5ffffffffff8dp3, 0x1.617398f2aa9d5p3},
                {0x1.0p0, 0x1.7ffffffffff9bp3, 0x1.8154be27734c1p3},
                {0x1.0p0, 0x1.8p3, 0x1.8154be2773526p3},
                {0x1.0p0, 0x1.9fffffffffff4p3, 0x1.a13a9cb996644p3},
                {0x1.0p0, 0x1.9ffffffffffffp3, 0x1.a13a9cb99664fp3},
                {0x1.0p0, 0x1.bfffffffffffep3, 0x1.c12432fec0327p3},
                {0x1.0p0, 0x1.cp3, 0x1.c12432fec0329p3},
                {0x1.0p0, 0x1.dffffffffffbcp3, 0x1.e110c39105f6bp3},
                {0x1.0p0, 0x1.ep3, 0x1.e110c39105fafp3},
                {0x1.0p0, 0x1.ffffffffffeafp3, 0x1.007fe00ff5fc8p4},
                {0x1.0p0, 0x1.0fffffffffff4p4, 0x1.10785dd689a1cp4},
                {0x1.0p0, 0x1.0fffffffffffbp4, 0x1.10785dd689a23p4},
                {0x1.0p0, 0x1.1ffffffffff92p4, 0x1.2071b0abcd7cap4},
                {0x1.0p0, 0x1.1ffffffffff99p4, 0x1.2071b0abcd7d1p4},
                {0x1.0p0, 0x1.2fffffffffffcp4, 0x1.306bb705ae7bfp4},
                {0x1.0p0, 0x1.2ffffffffffffp4, 0x1.306bb705ae7c3p4},
                {0x1.0p0, 0x1.3fffffffffffdp4, 0x1.4066560954a8bp4},
                {0x1.0p0, 0x1.4fffffffffe14p4, 0x1.506177f548fcfp4},
                {0x1.0p0, 0x1.5p4, 0x1.506177f5491bbp4},
                {0x1.0p0, 0x1.5fffffffffffdp4, 0x1.605d0af9d3a42p4},
                {0x1.0p0, 0x1.5fffffffffffep4, 0x1.605d0af9d3a42p4},
                {0x1.0p0, 0x1.6fffffffffff8p4, 0x1.7059005e2c015p4},
                {0x1.0p0, 0x1.6ffffffffffffp4, 0x1.7059005e2c01dp4},
                {0x1.0p0, 0x1.7fffffffffffdp4, 0x1.80554bdc2dc4dp4},
                {0x1.0p0, 0x1.7ffffffffffffp4, 0x1.80554bdc2dc4ep4},
                {0x1.0p0, 0x1.8fffffffffe68p4, 0x1.9051e3235a2cp4},
                {0x1.0p0, 0x1.9p4, 0x1.9051e3235a458p4},
                {0x1.0p0, 0x1.9fffffffffff4p4, 0x1.a04ebd789d00cp4},
                {0x1.0p0, 0x1.ap4, 0x1.a04ebd789d019p4},
                {0x1.0p0, 0x1.afffffffffed8p4, 0x1.b04bd36b639fbp4},
                {0x1.0p0, 0x1.affffffffff43p4, 0x1.b04bd36b63a66p4},
                {0x1.0p0, 0x1.bfffffffffe3ep4, 0x1.c0491e9ab90fdp4},
                {0x1.0p0, 0x1.cp4, 0x1.c0491e9ab92bfp4},
                {0x1.0p0, 0x1.cfffffffffed8p4, 0x1.d0469986884d6p4},
                {0x1.0p0, 0x1.cfffffffffee8p4, 0x1.d0469986884e5p4},
                {0x1.0p0, 0x1.dfffffffffe5cp4, 0x1.e0443f6a33104p4},
                {0x1.0p0, 0x1.dffffffffffffp4, 0x1.e0443f6a332a7p4},
                {0x1.0p0, 0x1.efffffffffff8p4, 0x1.f0420c1e63084p4},
                {0x1.0p0, 0x1.fp4, 0x1.f0420c1e6308dp4},
                {0x1.0p0, 0x1.ffffffffffffdp4, 0x1.001ffe003ff5fp5},
                {0x1.0p0, 0x1.07ffffffffed8p5, 0x1.081f05ef4d755p5},
                {0x1.0p0, 0x1.07ffffffffee8p5, 0x1.081f05ef4d764p5},
                {0x1.0p0, 0x1.0fffffffffff4p5, 0x1.101e1c7371c6bp5},
                {0x1.0p0, 0x1.0fffffffffffbp5, 0x1.101e1c7371c72p5},
                {0x1.0p0, 0x1.17ffffffffff8p5, 0x1.181d404cf7f51p5},
                {0x1.0p0, 0x1.17ffffffffffdp5, 0x1.181d404cf7f56p5},
                {0x1.0p0, 0x1.1fffffffffbf2p5, 0x1.201c705fa7a27p5},
                {0x1.0p0, 0x1.1fffffffffc65p5, 0x1.201c705fa7a9ap5},
                {0x1.0p0, 0x1.27ffffffffe08p5, 0x1.281babadfba01p5},
                {0x1.0p0, 0x1.28p5, 0x1.281babadfbbf9p5},
                {0x1.0p0, 0x1.2ffffffffff64p5, 0x1.301af15517357p5},
                {0x1.0p0, 0x1.2ffffffffff6cp5, 0x1.301af1551735ep5},
                {0x1.0p0, 0x1.37ffffffffc78p5, 0x1.381a40895d3f5p5},
                {0x1.0p0, 0x1.37ffffffffc88p5, 0x1.381a40895d406p5},
                {0x1.0p0, 0x1.3fffffffffffdp5, 0x1.4019989389b2dp5},
                {0x1.0p0, 0x1.4p5, 0x1.4019989389b3p5},
                {0x1.0p0, 0x1.47fffffffffe8p5, 0x1.4818f8ce34e19p5},
                {0x1.0p0, 0x1.47ffffffffffap5, 0x1.4818f8ce34e2cp5},
                {0x1.0p0, 0x1.4fffffffffa64p5, 0x1.501860a3b54bep5},
                {0x1.0p0, 0x1.4fffffffffe47p5, 0x1.501860a3b58a1p5},
                {0x1.0p0, 0x1.57ffffffffff8p5, 0x1.5817cf8c4c199p5},
                {0x1.0p0, 0x1.57fffffffffffp5, 0x1.5817cf8c4c1ap5},
                {0x1.0p0, 0x1.5fffffffffbeep5, 0x1.6017450c8d3e7p5},
                {0x1.0p0, 0x1.6p5, 0x1.6017450c8d7f9p5},
                {0x1.0p0, 0x1.67fffffffffe8p5, 0x1.6816c0b405afp5},
                {0x1.0p0, 0x1.68p5, 0x1.6816c0b405b09p5},
                {0x1.0p0, 0x1.6fffffffffb78p5, 0x1.7016421c06043p5},
                {0x1.0p0, 0x1.7p5, 0x1.7016421c064cbp5},
                {0x1.0p0, 0x1.77ffffffffffp5, 0x1.7815c8e69cc37p5},
                {0x1.0p0, 0x1.77ffffffffffcp5, 0x1.7815c8e69cc43p5},
                {0x1.0p0, 0x1.7ffffffffffffp5, 0x1.801554bda99c5p5},
                {0x1.0p0, 0x1.87fffffffffdp5, 0x1.8814e55214271p5},
                {0x1.0p0, 0x1.87ffffffffffcp5, 0x1.8814e5521429ep5},
                {0x1.0p0, 0x1.8ffffffffffe8p5, 0x1.90147a5b16ce5p5},
                {0x1.0p0, 0x1.8fffffffffffcp5, 0x1.90147a5b16cfap5},
                {0x1.0p0, 0x1.97ffffffffffp5, 0x1.98141395a0592p5},
                {0x1.0p0, 0x1.97fffffffffffp5, 0x1.98141395a05a1p5},
                {0x1.0p0, 0x1.9fffffffff8f4p5, 0x1.a013b0c3c7377p5},
                {0x1.0p0, 0x1.9fffffffffb18p5, 0x1.a013b0c3c759bp5},
                {0x1.0p0, 0x1.a7fffffffffdp5, 0x1.a81351ac4f317p5},
                {0x1.0p0, 0x1.a7ffffffffffp5, 0x1.a81351ac4f338p5},
                {0x1.0p0, 0x1.afffffffff698p5, 0x1.b012f61a35d98p5},
                {0x1.0p0, 0x1.bp5, 0x1.b012f61a367p5},
                {0x1.0p0, 0x1.b7ffffffff85p5, 0x1.b8129ddc56b26p5},
                {0x1.0p0, 0x1.b7ffffffff87p5, 0x1.b8129ddc56b45p5},
                {0x1.0p0, 0x1.bfffffffffffdp5, 0x1.c01248c50d99cp5},
                {0x1.0p0, 0x1.bfffffffffffep5, 0x1.c01248c50d99cp5},
                {0x1.0p0, 0x1.c7ffffffffedp5, 0x1.c811f6a9e9676p5},
                {0x1.0p0, 0x1.c8p5, 0x1.c811f6a9e97a6p5},
                {0x1.0p0, 0x1.cffffffffffe8p5, 0x1.d011a7636789ep5},
                {0x1.0p0, 0x1.d7ffffffffffp5, 0x1.d8115accb20f3p5},
                {0x1.0p0, 0x1.d8p5, 0x1.d8115accb2103p5},
                {0x1.0p0, 0x1.dfffffffffebcp5, 0x1.e01110c367a41p5},
                {0x1.0p0, 0x1.ep5, 0x1.e01110c367b85p5},
                {0x1.0p0, 0x1.e7fffffffffdp5, 0x1.e810c927681fap5},
                {0x1.0p0, 0x1.e8p5, 0x1.e810c9276822ap5},
                {0x1.0p0, 0x1.efffffffff7f8p5, 0x1.f01083daa4dadp5},
                {0x1.0p0, 0x1.fp5, 0x1.f01083daa55b5p5},
                {0x1.0p0, 0x1.f7ffffffffffp5, 0x1.f81040c0f9c6p5},
                {0x1.0p0, 0x1.f8p5, 0x1.f81040c0f9c71p5},
                {0x1.0p0, 0x1.fffffffffffffp5, 0x1.0007ffe000fffp6},
                {0x1.0p0, 0x1.03fffffffffdp6, 0x1.0407e05f7d188p6},
                {0x1.0p0, 0x1.03ffffffffffbp6, 0x1.0407e05f7d1b4p6},
                {0x1.0p0, 0x1.07ffffffff7f8p6, 0x1.0807c1d34edd5p6},
                {0x1.0p0, 0x1.07ffffffff808p6, 0x1.0807c1d34ede4p6},
                {0x1.0p0, 0x1.0bffffffff65p6, 0x1.0c07a430870e5p6},
                {0x1.0p0, 0x1.0bffffffff67p6, 0x1.0c07a43087104p6},
                {0x1.0p0, 0x1.0fffffffffc54p6, 0x1.1007876cda509p6},
                {0x1.0p0, 0x1.0fffffffffe0dp6, 0x1.1007876cda6c2p6},
                {0x1.0p0, 0x1.13fffffffffdp6, 0x1.14076b7e954b4p6},
                {0x1.0p0, 0x1.13ffffffffffep6, 0x1.14076b7e954e3p6},
                {0x1.0p0, 0x1.17ffffffffff8p6, 0x1.1807505c9310dp6},
                {0x1.0p0, 0x1.18p6, 0x1.1807505c93116p6},
                {0x1.0p0, 0x1.1bfffffffecbp6, 0x1.1c0735fe3197ap6},
                {0x1.0p0, 0x1.1bffffffff1dbp6, 0x1.1c0735fe31ea5p6},
                {0x1.0p0, 0x1.1ffffffffebcap6, 0x1.20071c5b4ce64p6},
                {0x1.0p0, 0x1.1fffffffffaf1p6, 0x1.20071c5b4dd8bp6},
                {0x1.0p0, 0x1.23ffffffff83p6, 0x1.2407036c309fdp6},
                {0x1.0p0, 0x1.23ffffffff85p6, 0x1.2407036c30a1cp6},
                {0x1.0p0, 0x1.27ffffffffba8p6, 0x1.2806eb2991e76p6},
                {0x1.0p0, 0x1.28p6, 0x1.2806eb29922cep6},
                {0x1.0p0, 0x1.2bfffffffff7p6, 0x1.2c06d38c8b4ffp6},
                {0x1.0p0, 0x1.2bfffffffff9p6, 0x1.2c06d38c8b52p6},
                {0x1.0p0, 0x1.2fffffffffff4p6, 0x1.3006bc8e938c8p6},
                {0x1.0p0, 0x1.2fffffffffffcp6, 0x1.3006bc8e938cfp6},
                {0x1.0p0, 0x1.33ffffffff87p6, 0x1.3406a6297821ep6},
                {0x1.0p0, 0x1.33ffffffff89p6, 0x1.3406a6297823dp6},
                {0x1.0p0, 0x1.37ffffffff9d8p6, 0x1.380690575943dp6},
                {0x1.0p0, 0x1.37ffffffff9eap6, 0x1.380690575944fp6},
                {0x1.0p0, 0x1.3bffffffffffp6, 0x1.3c067b12a2013p6},
                {0x1.0p0, 0x1.3cp6, 0x1.3c067b12a2024p6},
                {0x1.0p0, 0x1.3fffffffffe19p6, 0x1.40066656044ep6},
                {0x1.0p0, 0x1.4p6, 0x1.40066656046c7p6},
                {0x1.0p0, 0x1.43ffffffff1dp6, 0x1.4406521c75c3p6},
                {0x1.0p0, 0x1.43ffffffffccfp6, 0x1.4406521c7672fp6},
                {0x1.0p0, 0x1.47ffffffff8a8p6, 0x1.48063e612ce7ap6},
                {0x1.0p0, 0x1.47ffffffffcb9p6, 0x1.48063e612d28bp6},
                {0x1.0p0, 0x1.4bfffffffe1fp6, 0x1.4c062b1f96823p6},
                {0x1.0p0, 0x1.4cp6, 0x1.4c062b1f98633p6},
                {0x1.0p0, 0x1.4ffffffffde04p6, 0x1.500618535d07dp6},
                {0x1.0p0, 0x1.5p6, 0x1.500618535f279p6},
                {0x1.0p0, 0x1.53fffffffef1p6, 0x1.540605f85c637p6},
                {0x1.0p0, 0x1.53ffffffffdf3p6, 0x1.540605f85d51ap6},
                {0x1.0p0, 0x1.57ffffffffff8p6, 0x1.5805f40aa0595p6},
                {0x1.0p0, 0x1.5bffffffffffp6, 0x1.5c05e286636b5p6},
                {0x1.0p0, 0x1.5bfffffffffffp6, 0x1.5c05e286636c4p6},
                {0x1.0p0, 0x1.5ffffffffd9cep6, 0x1.6005d1680baa2p6},
                {0x1.0p0, 0x1.5fffffffff873p6, 0x1.6005d1680d947p6},
                {0x1.0p0, 0x1.63ffffffffa5p6, 0x1.6405c0ac30a35p6},
                {0x1.0p0, 0x1.63ffffffffa7p6, 0x1.6405c0ac30a56p6},
                {0x1.0p0, 0x1.67ffffffff988p6, 0x1.6805b04f83ac3p6},
                {0x1.0p0, 0x1.68p6, 0x1.6805b04f8413bp6},
                {0x1.0p0, 0x1.6bfffffffffep6, 0x1.6c05a04ee40c3p6},
                {0x1.0p0, 0x1.6cp6, 0x1.6c05a04ee40e3p6},
                {0x1.0p0, 0x1.6fffffffff018p6, 0x1.700590a74f9b5p6},
                {0x1.0p0, 0x1.6fffffffffbe2p6, 0x1.700590a75057fp6},
                {0x1.0p0, 0x1.73ffffffff4ap6, 0x1.74058155e9b72p6},
                {0x1.0p0, 0x1.74p6, 0x1.74058155ea6d2p6},
                {0x1.0p0, 0x1.77ffffffffffp6, 0x1.78057257f1868p6},
                {0x1.0p0, 0x1.78p6, 0x1.78057257f1878p6},
                {0x1.0p0, 0x1.7bfffffffffep6, 0x1.7c0563aac389bp6},
                {0x1.0p0, 0x1.7bfffffffffe4p6, 0x1.7c0563aac389fp6},
                {0x1.0p0, 0x1.7ffffffffffffp6, 0x1.8005554bda349p6},
                {0x1.0p0, 0x1.8p6, 0x1.8005554bda34bp6},
                {0x1.0p0, 0x1.83fffffffffap6, 0x1.84054738c9dcdp6},
                {0x1.0p0, 0x1.84p6, 0x1.84054738c9e2dp6},
                {0x1.0p0, 0x1.87ffffffff09p6, 0x1.8805396f3f494p6},
                {0x1.0p0, 0x1.87ffffffff0bp6, 0x1.8805396f3f4b5p6},
                {0x1.0p0, 0x1.8bfffffffffep6, 0x1.8c052bed02f7ap6},
                {0x1.0p0, 0x1.8cp6, 0x1.8c052bed02f9bp6},
                {0x1.0p0, 0x1.8fffffffff7c8p6, 0x1.90051eafee07bp6},
                {0x1.0p0, 0x1.9p6, 0x1.90051eafee8b3p6},
                {0x1.0p1, 0x1.fffffffffdcb5p-1, 0x1.1e3779b97f0b5p1},
                {0x1.0p1, 0x1.ffffffffffab5p0, 0x1.6a09e667f39edp1},
                {0x1.0p1, 0x1.7ffffffffffffp1, 0x1.cd82b446159f2p1},
                {0x1.0p1, 0x1.8p1, 0x1.cd82b446159f3p1},
                {0x1.0p1, 0x1.ffffffffffffbp1, 0x1.1e3779b97f4a6p2},
                {0x1.0p1, 0x1.3fffffffffffdp2, 0x1.58a68a4a8d9fp2},
                {0x1.0p1, 0x1.3fffffffffffep2, 0x1.58a68a4a8d9f1p2},
                {0x1.0p1, 0x1.7ffffffffffffp2, 0x1.94c583ada5b51p2},
                {0x1.0p1, 0x1.bfffffffffffep2, 0x1.d1ed52076fbe7p2},
                {0x1.0p1, 0x1.cp2, 0x1.d1ed52076fbe9p2},
                {0x1.0p1, 0x1.ffffffffffffdp2, 0x1.07e0f66afed06p3},
                {0x1.0p1, 0x1.1fffffffffff2p3, 0x1.2706821902e8cp3},
                {0x1.0p1, 0x1.2p3, 0x1.2706821902e9ap3},
                {0x1.0p1, 0x1.3fffffffffffdp3, 0x1.465655f122ff3p3},
                {0x1.0p1, 0x1.4p3, 0x1.465655f122ff6p3},
                {0x1.0p1, 0x1.5ffffffffffd6p3, 0x1.65c55827df1a8p3},
                {0x1.0p1, 0x1.7ffffffffffffp3, 0x1.854bfb363dc38p3},
                {0x1.0p1, 0x1.8p3, 0x1.854bfb363dc39p3},
                {0x1.0p1, 0x1.9ffffffffffe4p3, 0x1.a4e4efeda34c2p3},
                {0x1.0p1, 0x1.ap3, 0x1.a4e4efeda34dep3},
                {0x1.0p1, 0x1.bfffffffffffep3, 0x1.c48c6001f0abdp3},
                {0x1.0p1, 0x1.dfffffffffffcp3, 0x1.e43f746f77956p3},
                {0x1.0p1, 0x1.ep3, 0x1.e43f746f7795bp3},
                {0x1.0p1, 0x1.fffffffffffffp3, 0x1.01fe03f61badp4},
                {0x1.0p1, 0x1.0ffffffffffc4p4, 0x1.11e039f40ee2ap4},
                {0x1.0p1, 0x1.0ffffffffffc7p4, 0x1.11e039f40ee2dp4},
                {0x1.0p1, 0x1.1fffffffffffap4, 0x1.21c5b70d9f81dp4},
                {0x1.0p1, 0x1.2fffffffffffcp4, 0x1.31adf859f9e5ap4},
                {0x1.0p1, 0x1.2fffffffffffep4, 0x1.31adf859f9e5cp4},
                {0x1.0p1, 0x1.3ffffffffffe5p4, 0x1.419894c2329d5p4},
                {0x1.0p1, 0x1.3ffffffffffe7p4, 0x1.419894c2329d8p4},
                {0x1.0p1, 0x1.4fffffffffff4p4, 0x1.518536f3ca668p4},
                {0x1.0p1, 0x1.5p4, 0x1.518536f3ca675p4},
                {0x1.0p1, 0x1.5ffffffffff7ep4, 0x1.617398f2aa9c6p4},
                {0x1.0p1, 0x1.5ffffffffff8dp4, 0x1.617398f2aa9d5p4},
                {0x1.0p1, 0x1.6ffffffffffb8p4, 0x1.716380ce70352p4},
                {0x1.0p1, 0x1.7p4, 0x1.716380ce7039ap4},
                {0x1.0p1, 0x1.7ffffffffff9bp4, 0x1.8154be27734c1p4},
                {0x1.0p1, 0x1.8p4, 0x1.8154be2773526p4},
                {0x1.0p1, 0x1.8ffffffffffe8p4, 0x1.9147284a4142fp4},
                {0x1.0p1, 0x1.8ffffffffffffp4, 0x1.9147284a41446p4},
                {0x1.0p1, 0x1.9fffffffffff4p4, 0x1.a13a9cb996644p4},
                {0x1.0p1, 0x1.9ffffffffffffp4, 0x1.a13a9cb99664fp4},
                {0x1.0p1, 0x1.affffffffff58p4, 0x1.b12efe0a8f113p4},
                {0x1.0p1, 0x1.affffffffffd2p4, 0x1.b12efe0a8f18dp4},
                {0x1.0p1, 0x1.bfffffffffffep4, 0x1.c12432fec0327p4},
                {0x1.0p1, 0x1.cp4, 0x1.c12432fec0329p4},
                {0x1.0p1, 0x1.cffffffffffe8p4, 0x1.d11a25cd6ed78p4},
                {0x1.0p1, 0x1.dp4, 0x1.d11a25cd6ed91p4},
                {0x1.0p1, 0x1.dffffffffffbcp4, 0x1.e110c39105f6bp4},
                {0x1.0p1, 0x1.ep4, 0x1.e110c39105fafp4},
                {0x1.0p1, 0x1.effffffffffe8p4, 0x1.f107fbd0adcf1p4},
                {0x1.0p1, 0x1.efffffffffff8p4, 0x1.f107fbd0addp4},
                {0x1.0p1, 0x1.ffffffffffeafp4, 0x1.007fe00ff5fc8p5},
                {0x1.0p1, 0x1.07fffffffffe8p5, 0x1.087c01e7d5092p5},
                {0x1.0p1, 0x1.08p5, 0x1.087c01e7d50abp5},
                {0x1.0p1, 0x1.0fffffffffff4p5, 0x1.10785dd689a1cp5},
                {0x1.0p1, 0x1.0fffffffffffbp5, 0x1.10785dd689a23p5},
                {0x1.0p1, 0x1.17ffffffffed8p5, 0x1.1874eee5c5cb1p5},
                {0x1.0p1, 0x1.17ffffffffee8p5, 0x1.1874eee5c5cc2p5},
                {0x1.0p1, 0x1.1ffffffffff92p5, 0x1.2071b0abcd7cap5},
                {0x1.0p1, 0x1.1ffffffffff99p5, 0x1.2071b0abcd7d1p5},
                {0x1.0p1, 0x1.27ffffffffea8p5, 0x1.286e9f388de9fp5},
                {0x1.0p1, 0x1.28p5, 0x1.286e9f388dff7p5},
                {0x1.0p1, 0x1.2fffffffffffcp5, 0x1.306bb705ae7bfp5},
                {0x1.0p1, 0x1.2ffffffffffffp5, 0x1.306bb705ae7c3p5},
                {0x1.0p1, 0x1.37ffffffffff8p5, 0x1.3868f4e9108b9p5},
                {0x1.0p1, 0x1.38p5, 0x1.3868f4e9108c1p5},
                {0x1.0p1, 0x1.3fffffffffffdp5, 0x1.4066560954a8bp5},
                {0x1.0p1, 0x1.47ffffffffe28p5, 0x1.4863d7d40ad39p5},
                {0x1.0p1, 0x1.48p5, 0x1.4863d7d40af11p5},
                {0x1.0p1, 0x1.4fffffffffe14p5, 0x1.506177f548fcfp5},
                {0x1.0p1, 0x1.5p5, 0x1.506177f5491bbp5},
                {0x1.0p1, 0x1.57ffffffffeb8p5, 0x1.585f34506bafbp5},
                {0x1.0p1, 0x1.58p5, 0x1.585f34506bc43p5},
                {0x1.0p1, 0x1.5fffffffffffdp5, 0x1.605d0af9d3a42p5},
                {0x1.0p1, 0x1.5fffffffffffep5, 0x1.605d0af9d3a42p5},
                {0x1.0p1, 0x1.67ffffffffda8p5, 0x1.685afa317791bp5},
                {0x1.0p1, 0x1.68p5, 0x1.685afa3177b73p5},
                {0x1.0p1, 0x1.6fffffffffff8p5, 0x1.7059005e2c015p5},
                {0x1.0p1, 0x1.6ffffffffffffp5, 0x1.7059005e2c01dp5},
                {0x1.0p1, 0x1.77ffffffffffp5, 0x1.78571c0982328p5},
                {0x1.0p1, 0x1.78p5, 0x1.78571c0982339p5},
                {0x1.0p1, 0x1.7fffffffffffdp5, 0x1.80554bdc2dc4dp5},
                {0x1.0p1, 0x1.7ffffffffffffp5, 0x1.80554bdc2dc4ep5},
                {0x1.0p1, 0x1.87fffffffffdp5, 0x1.88538e9ad8dacp5},
                {0x1.0p1, 0x1.87fffffffffffp5, 0x1.88538e9ad8ddbp5},
                {0x1.0p1, 0x1.8fffffffffe68p5, 0x1.9051e3235a2cp5},
                {0x1.0p1, 0x1.9p5, 0x1.9051e3235a458p5},
                {0x1.0p1, 0x1.97ffffffffffp5, 0x1.9850486a3f17p5},
                {0x1.0p1, 0x1.97fffffffffffp5, 0x1.9850486a3f17fp5},
                {0x1.0p1, 0x1.9fffffffffff4p5, 0x1.a04ebd789d00cp5},
                {0x1.0p1, 0x1.ap5, 0x1.a04ebd789d019p5},
                {0x1.0p1, 0x1.a7ffffffffe1p5, 0x1.a84d416a2354dp5},
                {0x1.0p1, 0x1.a8p5, 0x1.a84d416a2373dp5},
                {0x1.0p1, 0x1.afffffffffed8p5, 0x1.b04bd36b639fbp5},
                {0x1.0p1, 0x1.affffffffff43p5, 0x1.b04bd36b63a66p5},
                {0x1.0p1, 0x1.b7ffffffffd7p5, 0x1.b84a72b848951p5},
                {0x1.0p1, 0x1.b7ffffffffe2bp5, 0x1.b84a72b848a0cp5},
                {0x1.0p1, 0x1.bfffffffffe3ep5, 0x1.c0491e9ab90fdp5},
                {0x1.0p1, 0x1.cp5, 0x1.c0491e9ab92bfp5},
                {0x1.0p1, 0x1.c7fffffffffdp5, 0x1.c847d6695dbc5p5},
                {0x1.0p1, 0x1.c8p5, 0x1.c847d6695dbf6p5},
                {0x1.0p1, 0x1.cfffffffffed8p5, 0x1.d0469986884d6p5},
                {0x1.0p1, 0x1.cfffffffffee8p5, 0x1.d0469986884e5p5},
                {0x1.0p1, 0x1.d7ffffffffdfp5, 0x1.d845675f37721p5},
                {0x1.0p1, 0x1.d8p5, 0x1.d845675f37931p5},
                {0x1.0p1, 0x1.dfffffffffe5cp5, 0x1.e0443f6a33104p5},
                {0x1.0p1, 0x1.dffffffffffffp5, 0x1.e0443f6a332a7p5},
                {0x1.0p1, 0x1.e7fffffffff05p5, 0x1.e84321273f31ep5},
                {0x1.0p1, 0x1.e7fffffffff1p5, 0x1.e84321273f328p5},
                {0x1.0p1, 0x1.efffffffffff8p5, 0x1.f0420c1e63084p5},
                {0x1.0p1, 0x1.fp5, 0x1.f0420c1e6308dp5},
                {0x1.0p1, 0x1.f7ffffffffc3p5, 0x1.f840ffdf40effp5},
                {0x1.0p1, 0x1.f7fffffffff08p5, 0x1.f840ffdf411d7p5},
                {0x1.0p1, 0x1.ffffffffffffdp5, 0x1.001ffe003ff5fp6},
                {0x1.0p1, 0x1.03fffffffffdp6, 0x1.041f800f9f928p6},
                {0x1.0p1, 0x1.03ffffffffffap6, 0x1.041f800f9f953p6},
                {0x1.0p1, 0x1.07ffffffffed8p6, 0x1.081f05ef4d755p6},
                {0x1.0p1, 0x1.07ffffffffee8p6, 0x1.081f05ef4d764p6},
                {0x1.0p1, 0x1.0bfffffffff5p6, 0x1.0c1e8f739cdcap6},
                {0x1.0p1, 0x1.0bfffffffff7p6, 0x1.0c1e8f739cde9p6},
                {0x1.0p1, 0x1.0fffffffffff4p6, 0x1.101e1c7371c6bp6},
                {0x1.0p1, 0x1.0fffffffffffbp6, 0x1.101e1c7371c72p6},
                {0x1.0p1, 0x1.13fffffffffdp6, 0x1.141dacc811a34p6},
                {0x1.0p1, 0x1.13ffffffffffcp6, 0x1.141dacc811a6p6},
                {0x1.0p1, 0x1.17ffffffffff8p6, 0x1.181d404cf7f51p6},
                {0x1.0p1, 0x1.17ffffffffffdp6, 0x1.181d404cf7f56p6},
                {0x1.0p1, 0x1.1bffffffffffp6, 0x1.1c1cd6dfae4a5p6},
                {0x1.0p1, 0x1.1bffffffffffep6, 0x1.1c1cd6dfae4b4p6},
                {0x1.0p1, 0x1.1fffffffffbf2p6, 0x1.201c705fa7a27p6},
                {0x1.0p1, 0x1.1fffffffffc65p6, 0x1.201c705fa7a9ap6},
                {0x1.0p1, 0x1.23fffffffffdp6, 0x1.241c0cae201cap6},
                {0x1.0p1, 0x1.23ffffffffffp6, 0x1.241c0cae201ebp6},
                {0x1.0p1, 0x1.27ffffffffe08p6, 0x1.281babadfba01p6},
                {0x1.0p1, 0x1.28p6, 0x1.281babadfbbf9p6},
                {0x1.0p1, 0x1.2bffffffffc1p6, 0x1.2c1b4d43ac4cfp6},
                {0x1.0p1, 0x1.2bffffffffc3p6, 0x1.2c1b4d43ac4eep6},
                {0x1.0p1, 0x1.2ffffffffff64p6, 0x1.301af15517357p6},
                {0x1.0p1, 0x1.2ffffffffff6cp6, 0x1.301af1551735ep6},
                {0x1.0p1, 0x1.33ffffffffadp6, 0x1.341a97c97b22ep6},
                {0x1.0p1, 0x1.33ffffffffafp6, 0x1.341a97c97b24fp6},
                {0x1.0p1, 0x1.37ffffffffc78p6, 0x1.381a40895d3f5p6},
                {0x1.0p1, 0x1.37ffffffffc88p6, 0x1.381a40895d406p6},
                {0x1.0p1, 0x1.3bffffffffffp6, 0x1.3c19eb7e71afcp6},
                {0x1.0p1, 0x1.3bfffffffffffp6, 0x1.3c19eb7e71b0cp6},
                {0x1.0p1, 0x1.3fffffffffffdp6, 0x1.4019989389b2dp6},
                {0x1.0p1, 0x1.4p6, 0x1.4019989389b3p6},
                {0x1.0p1, 0x1.43fffffffffdp6, 0x1.441947b4829e8p6},
                {0x1.0p1, 0x1.43ffffffffff8p6, 0x1.441947b482a11p6},
                {0x1.0p1, 0x1.47fffffffffe8p6, 0x1.4818f8ce34e19p6},
                {0x1.0p1, 0x1.47ffffffffffap6, 0x1.4818f8ce34e2cp6},
                {0x1.0p1, 0x1.4bffffffffffp6, 0x1.4c18abce6501fp6},
                {0x1.0p1, 0x1.4bffffffffffcp6, 0x1.4c18abce6502cp6},
                {0x1.0p1, 0x1.4fffffffffa64p6, 0x1.501860a3b54bep6},
                {0x1.0p1, 0x1.4fffffffffe47p6, 0x1.501860a3b58a1p6},
                {0x1.0p1, 0x1.53ffffffffd5p6, 0x1.5418173d9a501p6},
                {0x1.0p1, 0x1.53ffffffffd7p6, 0x1.5418173d9a522p6},
                {0x1.0p1, 0x1.57ffffffffff8p6, 0x1.5817cf8c4c199p6},
                {0x1.0p1, 0x1.57fffffffffffp6, 0x1.5817cf8c4c1ap6},
                {0x1.0p1, 0x1.5bffffffff83p6, 0x1.5c178980bc34bp6},
                {0x1.0p1, 0x1.5bffffffff988p6, 0x1.5c178980bc4a3p6},
                {0x1.0p1, 0x1.5fffffffffbeep6, 0x1.6017450c8d3e7p6},
                {0x1.0p1, 0x1.6p6, 0x1.6017450c8d7f9p6},
                {0x1.0p1, 0x1.63fffffffffdp6, 0x1.6417022204f99p6},
                {0x1.0p1, 0x1.67fffffffffe8p6, 0x1.6816c0b405afp6},
                {0x1.0p1, 0x1.68p6, 0x1.6816c0b405b09p6},
                {0x1.0p1, 0x1.6bfffffffffep6, 0x1.6c1680b6059e8p6},
                {0x1.0p1, 0x1.6cp6, 0x1.6c1680b605a08p6},
                {0x1.0p1, 0x1.6fffffffffb78p6, 0x1.7016421c06043p6},
                {0x1.0p1, 0x1.7p6, 0x1.7016421c064cbp6},
                {0x1.0p1, 0x1.73fffffffffap6, 0x1.741604da8d2b9p6},
                {0x1.0p1, 0x1.73ffffffffff8p6, 0x1.741604da8d311p6},
                {0x1.0p1, 0x1.77ffffffffffp6, 0x1.7815c8e69cc37p6},
                {0x1.0p1, 0x1.77ffffffffffcp6, 0x1.7815c8e69cc43p6},
                {0x1.0p1, 0x1.7bfffffffffep6, 0x1.7c158e35adde4p6},
                {0x1.0p1, 0x1.7bfffffffffe8p6, 0x1.7c158e35addecp6},
                {0x1.0p1, 0x1.7ffffffffffffp6, 0x1.801554bda99c5p6},
                {0x1.0p1, 0x1.83ffffffffdap6, 0x1.84151c74e35e4p6},
                {0x1.0p1, 0x1.83ffffffffdep6, 0x1.84151c74e3625p6},
                {0x1.0p1, 0x1.87fffffffffdp6, 0x1.8814e55214271p6},
                {0x1.0p1, 0x1.87ffffffffffcp6, 0x1.8814e5521429ep6},
                {0x1.0p1, 0x1.8bfffffffffep6, 0x1.8c14af4c540b6p6},
                {0x1.0p1, 0x1.8bffffffffff6p6, 0x1.8c14af4c540cdp6},
                {0x1.0p1, 0x1.8ffffffffffe8p6, 0x1.90147a5b16ce5p6},
                {0x1.0p1, 0x1.8fffffffffffcp6, 0x1.90147a5b16cfap6},
                {0x1.8p1, 0x1.ffffffffffffdp-1, 0x1.94c583ada5b53p1},
                {0x1.8p1, 0x1.0p1, 0x1.cd82b446159f3p1},
                {0x1.8p1, 0x1.7fffffffffff7p1, 0x1.0f876ccdf6cd6p2},
                {0x1.8p1, 0x1.8p1, 0x1.0f876ccdf6cd9p2},
                {0x1.8p1, 0x1.fffffffffffffp1, 0x1.4p2},
                {0x1.8p1, 0x1.3ffffffffffe1p2, 0x1.752e50db3a387p2},
                {0x1.8p1, 0x1.4p2, 0x1.752e50db3a3a2p2},
                {0x1.8p1, 0x1.7ffffffffffffp2, 0x1.ad5336963eefap2},
                {0x1.8p1, 0x1.bfffffffffffep2, 0x1.e768d399dc46dp2},
                {0x1.8p1, 0x1.bffffffffffffp2, 0x1.e768d399dc46fp2},
                {0x1.8p1, 0x1.fffffffffffffp2, 0x1.11687a8ae14a3p3},
                {0x1.8p1, 0x1.1fffffffffff2p3, 0x1.2f9422c23c47p3},
                {0x1.8p1, 0x1.1fffffffffff7p3, 0x1.2f9422c23c475p3},
                {0x1.8p1, 0x1.3fffffffffff1p3, 0x1.4e16fdacff928p3},
                {0x1.8p1, 0x1.3fffffffffff4p3, 0x1.4e16fdacff92bp3},
                {0x1.8p1, 0x1.5ffffffffffffp3, 0x1.6cdb2bbb212ebp3},
                {0x1.8p1, 0x1.7fffffffffffdp3, 0x1.8bd171a07e388p3},
                {0x1.8p1, 0x1.7ffffffffffffp3, 0x1.8bd171a07e389p3},
                {0x1.8p1, 0x1.9ffffffffffe4p3, 0x1.aaeee979b481cp3},
                {0x1.8p1, 0x1.9ffffffffffecp3, 0x1.aaeee979b4825p3},
                {0x1.8p1, 0x1.bffffffffffeep3, 0x1.ca2b9714180e5p3},
                {0x1.8p1, 0x1.cp3, 0x1.ca2b9714180f7p3},
                {0x1.8p1, 0x1.dfffffffffffcp3, 0x1.e98180e9b47edp3},
                {0x1.8p1, 0x1.dfffffffffffep3, 0x1.e98180e9b47efp3},
                {0x1.8p1, 0x1.fffffffffffffp3, 0x1.04760c95db31p4},
                {0x1.8p1, 0x1.0fffffffffff4p4, 0x1.1433ec467efefp4},
                {0x1.8p1, 0x1.1ffffffffffeap4, 0x1.23f8fc68ae515p4},
                {0x1.8p1, 0x1.2p4, 0x1.23f8fc68ae52bp4},
                {0x1.8p1, 0x1.2fffffffffffcp4, 0x1.33c42213ee0c5p4},
                {0x1.8p1, 0x1.3p4, 0x1.33c42213ee0c9p4},
                {0x1.8p1, 0x1.3ffffffffffd9p4, 0x1.439479381ec96p4},
                {0x1.8p1, 0x1.3fffffffffff6p4, 0x1.439479381ecb3p4},
                {0x1.8p1, 0x1.4ffffffffffc4p4, 0x1.53694801747d4p4},
                {0x1.8p1, 0x1.4ffffffffffccp4, 0x1.53694801747dcp4},
                {0x1.8p1, 0x1.5ffffffffffbep4, 0x1.6341f58bad9d2p4},
                {0x1.8p1, 0x1.5ffffffffffc2p4, 0x1.6341f58bad9d7p4},
                {0x1.8p1, 0x1.6fffffffffff8p4, 0x1.731e02ed21f18p4},
                {0x1.8p1, 0x1.6ffffffffffffp4, 0x1.731e02ed21f2p4},
                {0x1.8p1, 0x1.7fffffffffffdp4, 0x1.82fd05f129836p4},
                {0x1.8p1, 0x1.7ffffffffffffp4, 0x1.82fd05f129837p4},
                {0x1.8p1, 0x1.8ffffffffffa8p4, 0x1.92dea50d28578p4},
                {0x1.8p1, 0x1.8ffffffffffffp4, 0x1.92dea50d285cep4},
                {0x1.8p1, 0x1.9ffffffffffe4p4, 0x1.a2c2943e2866p4},
                {0x1.8p1, 0x1.9fffffffffffcp4, 0x1.a2c2943e28678p4},
                {0x1.8p1, 0x1.afffffffffff8p4, 0x1.b2a892946f42dp4},
                {0x1.8p1, 0x1.afffffffffffep4, 0x1.b2a892946f434p4},
                {0x1.8p1, 0x1.bffffffffffeep4, 0x1.c2906842b6bf3p4},
                {0x1.8p1, 0x1.bfffffffffff2p4, 0x1.c2906842b6bf8p4},
                {0x1.8p1, 0x1.cffffffffffe8p4, 0x1.d279e51208c72p4},
                {0x1.8p1, 0x1.dp4, 0x1.d279e51208c8ap4},
                {0x1.8p1, 0x1.dfffffffffff4p4, 0x1.e264df234beddp4},
                {0x1.8p1, 0x1.dfffffffffffcp4, 0x1.e264df234bee4p4},
                {0x1.8p1, 0x1.efffffffffff8p4, 0x1.f25131ed54d64p4},
                {0x1.8p1, 0x1.fp4, 0x1.f25131ed54d6cp4},
                {0x1.8p1, 0x1.fffffffffffffp4, 0x1.011f5eb54147p5},
                {0x1.8p1, 0x1.07fffffffff88p5, 0x1.0916b2b5fff3ep5},
                {0x1.8p1, 0x1.07fffffffffaap5, 0x1.0916b2b5fff6p5},
                {0x1.8p1, 0x1.0ffffffffffc4p5, 0x1.110e8885865b8p5},
                {0x1.8p1, 0x1.0ffffffffffccp5, 0x1.110e8885865c1p5},
                {0x1.8p1, 0x1.17fffffffff58p5, 0x1.1906d51932b7ep5},
                {0x1.8p1, 0x1.17fffffffff77p5, 0x1.1906d51932b9dp5},
                {0x1.8p1, 0x1.1fffffffffffap5, 0x1.20ff8e9d967d6p5},
                {0x1.8p1, 0x1.1fffffffffffep5, 0x1.20ff8e9d967dbp5},
                {0x1.8p1, 0x1.27fffffffffc8p5, 0x1.28f8ac4cd98f2p5},
                {0x1.8p1, 0x1.27fffffffffd8p5, 0x1.28f8ac4cd9903p5},
                {0x1.8p1, 0x1.2ffffffffff7cp5, 0x1.30f2264b9c502p5},
                {0x1.8p1, 0x1.2ffffffffffafp5, 0x1.30f2264b9c535p5},
                {0x1.8p1, 0x1.37ffffffffff8p5, 0x1.38ebf58b30cb4p5},
                {0x1.8p1, 0x1.37fffffffffffp5, 0x1.38ebf58b30cbcp5},
                {0x1.8p1, 0x1.3fffffffffffdp5, 0x1.40e613b03f1dcp5},
                {0x1.8p1, 0x1.3ffffffffffffp5, 0x1.40e613b03f1dfp5},
                {0x1.8p1, 0x1.47fffffffffa1p5, 0x1.48e07afd169d5p5},
                {0x1.8p1, 0x1.47fffffffffa8p5, 0x1.48e07afd169dbp5},
                {0x1.8p1, 0x1.4ffffffffff84p5, 0x1.50db263f101e3p5},
                {0x1.8p1, 0x1.4ffffffffff8cp5, 0x1.50db263f101ecp5},
                {0x1.8p1, 0x1.57ffffffffff8p5, 0x1.58d610be831eep5},
                {0x1.8p1, 0x1.58p5, 0x1.58d610be831f7p5},
                {0x1.8p1, 0x1.5fffffffffffap5, 0x1.60d13630e611p5},
                {0x1.8p1, 0x1.5fffffffffffep5, 0x1.60d13630e6113p5},
                {0x1.8p1, 0x1.67fffffffffe8p5, 0x1.68cc92acc47abp5},
                {0x1.8p1, 0x1.68p5, 0x1.68cc92acc47c3p5},
                {0x1.8p1, 0x1.6fffffffffff8p5, 0x1.70c8229f43a38p5},
                {0x1.8p1, 0x1.6fffffffffffap5, 0x1.70c8229f43a3ap5},
                {0x1.8p1, 0x1.77ffffffffffp5, 0x1.78c3e2c2fb433p5},
                {0x1.8p1, 0x1.77ffffffffffep5, 0x1.78c3e2c2fb441p5},
                {0x1.8p1, 0x1.7ffffffffffffp5, 0x1.80bfd017f10a6p5},
                {0x1.8p1, 0x1.87fffffffff5p5, 0x1.88bbe7dc8d9ap5},
                {0x1.8p1, 0x1.88p5, 0x1.88bbe7dc8da5p5},
                {0x1.8p1, 0x1.8ffffffffffe8p5, 0x1.90b8278768b67p5},
                {0x1.8p1, 0x1.9p5, 0x1.90b8278768b8p5},
                {0x1.8p1, 0x1.97fffffffff2bp5, 0x1.98b48cc1ce669p5},
                {0x1.8p1, 0x1.97fffffffff3p5, 0x1.98b48cc1ce66dp5},
                {0x1.8p1, 0x1.9ffffffffff34p5, 0x1.a0b11562e5efcp5},
                {0x1.8p1, 0x1.ap5, 0x1.a0b11562e5fc8p5},
                {0x1.8p1, 0x1.a7fffffffffdp5, 0x1.a8adbf6b63874p5},
                {0x1.8p1, 0x1.a8p5, 0x1.a8adbf6b638a4p5},
                {0x1.8p1, 0x1.affffffffffd8p5, 0x1.b0aa8901b442cp5},
                {0x1.8p1, 0x1.affffffffffe8p5, 0x1.b0aa8901b443dp5},
                {0x1.8p1, 0x1.b7ffffffffffp5, 0x1.b8a7706e94761p5},
                {0x1.8p1, 0x1.b7ffffffffffep5, 0x1.b8a7706e9477p5},
                {0x1.8p1, 0x1.bfffffffffffep5, 0x1.c0a4741a02dcap5},
                {0x1.8p1, 0x1.cp5, 0x1.c0a4741a02dcdp5},
                {0x1.8p1, 0x1.c7fffffffffdp5, 0x1.c8a1928885b75p5},
                {0x1.8p1, 0x1.c7ffffffffff9p5, 0x1.c8a1928885b9fp5},
                {0x1.8p1, 0x1.cffffffffff28p5, 0x1.d09eca58b7d2cp5},
                {0x1.8p1, 0x1.dp5, 0x1.d09eca58b7e04p5},
                {0x1.8p1, 0x1.d7ffffffffffp5, 0x1.d89c1a4115253p5},
                {0x1.8p1, 0x1.d8p5, 0x1.d89c1a4115264p5},
                {0x1.8p1, 0x1.dfffffffffffcp5, 0x1.e099810dfefd1p5},
                {0x1.8p1, 0x1.e7fffffffffdp5, 0x1.e896fd9ff2afep5},
                {0x1.8p1, 0x1.e7ffffffffffap5, 0x1.e896fd9ff2b29p5},
                {0x1.8p1, 0x1.effffffffff98p5, 0x1.f0948ee9ebc7bp5},
                {0x1.8p1, 0x1.effffffffffcap5, 0x1.f0948ee9ebcadp5},
                {0x1.8p1, 0x1.f7fffffffff7p5, 0x1.f89233efeda08p5},
                {0x1.8p1, 0x1.f7fffffffffb2p5, 0x1.f89233efeda4ap5},
                {0x1.8p1, 0x1.ffffffffffda9p5, 0x1.0047f5e2d7ed7p6},
                {0x1.8p1, 0x1.03ffffffffedp6, 0x1.0446dac6b5468p6},
                {0x1.8p1, 0x1.04p6, 0x1.0446dac6b5598p6},
                {0x1.8p1, 0x1.07fffffffffe8p6, 0x1.0845c83b5eb9bp6},
                {0x1.8p1, 0x1.07ffffffffff9p6, 0x1.0845c83b5ebadp6},
                {0x1.8p1, 0x1.0bffffffffe9bp6, 0x1.0c44bdded82bdp6},
                {0x1.8p1, 0x1.0bffffffffebp6, 0x1.0c44bdded82d1p6},
                {0x1.8p1, 0x1.0fffffffffed4p6, 0x1.1043bb54e5cc9p6},
                {0x1.8p1, 0x1.0ffffffffff1fp6, 0x1.1043bb54e5d14p6},
                {0x1.8p1, 0x1.13ffffffffe9p6, 0x1.1442c046a0ea6p6},
                {0x1.8p1, 0x1.13fffffffff5ap6, 0x1.1442c046a0f7p6},
                {0x1.8p1, 0x1.17fffffffffa8p6, 0x1.1841cc62174cbp6},
                {0x1.8p1, 0x1.17fffffffffb8p6, 0x1.1841cc62174dap6},
                {0x1.8p1, 0x1.1bffffffffffp6, 0x1.1c40df59f1a57p6},
                {0x1.8p1, 0x1.1cp6, 0x1.1c40df59f1a67p6},
                {0x1.8p1, 0x1.1fffffffffffap6, 0x1.203ff8e522535p6},
                {0x1.8p1, 0x1.1ffffffffffffp6, 0x1.203ff8e52253bp6},
                {0x1.8p1, 0x1.23fffffffffdp6, 0x1.243f18be9a334p6},
                {0x1.8p1, 0x1.23ffffffffffbp6, 0x1.243f18be9a36p6},
                {0x1.8p1, 0x1.27fffffffffe8p6, 0x1.283e3ea503c63p6},
                {0x1.8p1, 0x1.27ffffffffff8p6, 0x1.283e3ea503c74p6},
                {0x1.8p1, 0x1.2bffffffffdfp6, 0x1.2c3d6a5a83932p6},
                {0x1.8p1, 0x1.2bffffffffe1p6, 0x1.2c3d6a5a83953p6},
                {0x1.8p1, 0x1.2fffffffffffcp6, 0x1.303c9ba47e6d4p6},
                {0x1.8p1, 0x1.3p6, 0x1.303c9ba47e6d8p6},
                {0x1.8p1, 0x1.33fffffffffdp6, 0x1.343bd24b62468p6},
                {0x1.8p1, 0x1.33fffffffffffp6, 0x1.343bd24b62498p6},
                {0x1.8p1, 0x1.37ffffffffff8p6, 0x1.383b0e1a75c0ap6},
                {0x1.8p1, 0x1.37fffffffffffp6, 0x1.383b0e1a75c12p6},
                {0x1.8p1, 0x1.3bffffffffffp6, 0x1.3c3a4edfa9748p6},
                {0x1.8p1, 0x1.3bffffffffffep6, 0x1.3c3a4edfa9756p6},
                {0x1.8p1, 0x1.3fffffffffd4dp6, 0x1.4039946b6d79fp6},
                {0x1.8p1, 0x1.3ffffffffffffp6, 0x1.4039946b6da51p6},
                {0x1.8p1, 0x1.43fffffffff9p6, 0x1.4438de908abeap6},
                {0x1.8p1, 0x1.43fffffffffbp6, 0x1.4438de908ac0bp6},
                {0x1.8p1, 0x1.47ffffffffd08p6, 0x1.48382d23fccedp6},
                {0x1.8p1, 0x1.47fffffffffa2p6, 0x1.48382d23fcf87p6},
                {0x1.8p1, 0x1.4bffffffffcebp6, 0x1.4c377ffcd212fp6},
                {0x1.8p1, 0x1.4bffffffffcfp6, 0x1.4c377ffcd2133p6},
                {0x1.8p1, 0x1.4ffffffffff44p6, 0x1.5036d6f40ad53p6},
                {0x1.8p1, 0x1.4ffffffffff9bp6, 0x1.5036d6f40adaap6},
                {0x1.8p1, 0x1.53ffffffffedp6, 0x1.543631e47c1e1p6},
                {0x1.8p1, 0x1.54p6, 0x1.543631e47c311p6},
                {0x1.8p1, 0x1.57ffffffffd78p6, 0x1.583590aab542dp6},
                {0x1.8p1, 0x1.58p6, 0x1.583590aab56b5p6},
                {0x1.8p1, 0x1.5bffffffffc7p6, 0x1.5c34f324e60eep6},
                {0x1.8p1, 0x1.5bffffffffc9p6, 0x1.5c34f324e610fp6},
                {0x1.8p1, 0x1.5fffffffffffdp6, 0x1.60345932c760dp6},
                {0x1.8p1, 0x1.5fffffffffffep6, 0x1.60345932c760dp6},
                {0x1.8p1, 0x1.63fffffffff79p6, 0x1.6433c2b58421fp6},
                {0x1.8p1, 0x1.63fffffffff9p6, 0x1.6433c2b584235p6},
                {0x1.8p1, 0x1.67ffffffffda8p6, 0x1.68332f8fa63a6p6},
                {0x1.8p1, 0x1.67fffffffff4dp6, 0x1.68332f8fa654bp6},
                {0x1.8p1, 0x1.6bfffffffffep6, 0x1.6c329fa502ccfp6},
                {0x1.8p1, 0x1.6cp6, 0x1.6c329fa502cefp6},
                {0x1.8p1, 0x1.6fffffffffff8p6, 0x1.703212daa75f3p6},
                {0x1.8p1, 0x1.6ffffffffffffp6, 0x1.703212daa75fbp6},
                {0x1.8p1, 0x1.73fffffffffap6, 0x1.74318916ca409p6},
                {0x1.8p1, 0x1.74p6, 0x1.74318916ca46ap6},
                {0x1.8p1, 0x1.77ffffffffffp6, 0x1.78310240ba47p6},
                {0x1.8p1, 0x1.78p6, 0x1.78310240ba481p6},
                {0x1.8p1, 0x1.7bfffffffffep6, 0x1.7c307e40cff7fp6},
                {0x1.8p1, 0x1.7bfffffffffe4p6, 0x1.7c307e40cff83p6},
                {0x1.8p1, 0x1.7fffffffffff7p6, 0x1.802ffd005ff07p6},
                {0x1.8p1, 0x1.7fffffffffff9p6, 0x1.802ffd005ff0ap6},
                {0x1.8p1, 0x1.83fffffffffap6, 0x1.842f7e69adc1ep6},
                {0x1.8p1, 0x1.83fffffffffffp6, 0x1.842f7e69adc7dp6},
                {0x1.8p1, 0x1.87fffffffffdp6, 0x1.882f0267dfef4p6},
                {0x1.8p1, 0x1.88p6, 0x1.882f0267dff24p6},
                {0x1.8p1, 0x1.8bfffffffffep6, 0x1.8c2e88e6f449ap6},
                {0x1.8p1, 0x1.8bffffffffff6p6, 0x1.8c2e88e6f44b1p6},
                {0x1.8p1, 0x1.8ffffffffffe8p6, 0x1.902e11d3b5549p6},
                {0x1.8p1, 0x1.8fffffffffffep6, 0x1.902e11d3b556p6},

                // Test near decision points of the fdlibm algorithm
                {0x1.0000000000001p501, 0x1.000000000000p501, 0x1.6a09e667f3bcdp501},
                {0x1.0p501, 0x1.0p499, 0x1.07e0f66afed07p501},

                {0x1.0p500, 0x1.0p450, 0x1.0p500},
                {0x1.0000000000001p500, 0x1.0p450, 0x1.0000000000001p500},

                {0x1.0p500, 0x1.0p440, 0x1.0p500},
                {0x1.0000000000001p500, 0x1.0p440, 0x1.0000000000001p500},
                {0x1.0p500, 0x1.0p439, 0x1.0p500},
                {0x1.0000000000001p500, 0x1.0p439, 0x1.0000000000001p500},

                {0x1.0p-450, 0x1.0p-500, 0x1.0p-450},
                {0x1.0000000000001p-450, 0x1.0p-500, 0x1.0000000000001p-450},
                {0x1.0p-450, 0x1.fffffffffffffp-499, 0x1.0p-450},
                {0x1.0000000000001p-450, 0x1.fffffffffffffp-499, 0x1.0000000000001p-450},

                {0x1.0p-450, 0x1.0p-500, 0x1.0p-450},
                {0x1.0000000000001p-450, 0x1.0p-500, 0x1.0000000000001p-450},
                {0x1.0p-450, 0x1.fffffffffffffp-499, 0x1.0p-450},
                {0x1.0000000000001p-450, 0x1.fffffffffffffp-499, 0x1.0000000000001p-450},

                {0x1.00000_ffff_0000p500, 0x1.fffffffffffffp499, 0x1.6a09f1b837ccfp500},
                {0x1.00000_0000_0001p500, 0x1.fffffffffffffp499, 0x1.6a09e667f3bcdp500},
                {0x1.00000_ffff_ffffp500, 0x1.fffffffffffffp499, 0x1.6a09f1b8431d3p500},
                {0x1.00001_0000_0000p500, 0x1.fffffffffffffp499, 0x1.6a09f1b8431d5p500},

                // 0x1.0p-1022 is MIN_NORMAL
                {0x1.0000000000001p-1022, 0x1.0000000000001p-1022, 0x1.6a09e667f3bcep-1022},
                {0x1.0000000000001p-1022, 0x1.0p-1022, 0x1.6a09e667f3bcdp-1022},
                {0x1.0000000000001p-1022, 0x0.fffffffffffffp-1022, 0x1.6a09e667f3bcdp-1022},
                {0x1.0000000000001p-1022, 0x0.0000000000001P-1022, 0x1.0000000000001p-1022},
                {0x1.0000000000001p-1022, 0.0, 0x1.0000000000001p-1022},

                {0x1.0000000000000p-1022, 0x0.fffffffffffffp-1022, 0x1.6a09e667f3bccp-1022},
                {0x1.0000000000000p-1021, 0x0.fffffffffffffp-1022, 0x1.1e3779b97f4a8p-1021},
                {0x1.0000000000000p-1020, 0x0.fffffffffffffp-1022, 0x1.07e0f66afed07p-1020},

                // 0x0.0000000000001P-1022 is MIN_VALUE (smallest nonzero number)
                {0x0.0000000000001p-1022, 0x0.0000000000001p-1022, 0x0.0000000000001p-1022},
                {0x0.0000000000002p-1022, 0x0.0000000000001p-1022, 0x0.0000000000002p-1022},
                {0x0.0000000000003p-1022, 0x0.0000000000002p-1022, 0x0.0000000000004p-1022},
        };

        for (double[] testCase : testCases) {
            testHypotCase(testCase[0], testCase[1], testCase[2]);
        }
    }

    // Initialize shared random number generator
    private static final java.util.Random random = new Random();
    // BEGIN Android-added: Shard testAgainstTranslit() to make tests run faster.
    private static double X = Tests.createRandomDouble(random);
    private static double Y = Tests.createRandomDouble(random);
    // END Android-added: Shard testAgainstTranslit() to make tests run faster.

    // BEGIN Android-changed: Shard testAgainstTranslit() to make tests run faster.
    /**
     * Test StrictMath.hypot against transliteration port of hypot.
     *
    @Test
    public void testAgainstTranslit() {
        double x = Tests.createRandomDouble(random);
        double y = Tests.createRandomDouble(random);

        // Make the increment twice the ulp value in case the random
        // value is near an exponent threshold.
        double increment_x = 2.0 * Math.ulp(x);
        double increment_y = 2.0 * Math.ulp(y);

        // Don't worry about x or y overflowing to infinity if their
        // exponent is MAX_EXPONENT.
        for (int i = 0; i < 200; i++, x += increment_x) {
            for (int j = 0; j < 200; j++, y += increment_y) {
                testHypotCase(x, y, FdlibmTranslit.hypot(x, y));
            }
        }
    }
    */
    @LargeTest
    @Test
    public void testAgainstTranslit_shard1() {
        testAgainstTranslit(0, 20);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard2() {
        testAgainstTranslit(20, 40);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard3() {
        testAgainstTranslit(40, 60);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard4() {
        testAgainstTranslit(60, 80);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard5() {
        testAgainstTranslit(80, 100);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard6() {
        testAgainstTranslit(100, 120);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard7() {
        testAgainstTranslit(120, 140);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard8() {
        testAgainstTranslit(140, 160);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard9() {
        testAgainstTranslit(160, 180);
    }

    @LargeTest
    @Test
    public void testAgainstTranslit_shard10() {
        testAgainstTranslit(180, 200);
    }


    private void testAgainstTranslit(int fromI, int toI) {
        // Make the increment twice the ulp value in case the random
        // value is near an exponent threshold.
        double increment_x = 2.0 * Math.ulp(X);
        double increment_y = 2.0 * Math.ulp(Y);

        // Don't worry about x or y overflowing to infinity if their
        // exponent is MAX_EXPONENT.
        for (int i = fromI; i < toI; i++, X += increment_x) {
            for (int j = 0; j < 200; j++, Y += increment_y) {
                testHypotCase(X, Y, FdlibmTranslit.hypot(X, Y));
            }
        }
    }
    // END Android-changed: Shard testAgainstTranslit() to make tests run faster.
}
