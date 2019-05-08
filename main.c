#include <wmmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>

void AES_128_Key_Expansion (const unsigned char *userkey,
                            unsigned char *key);

/*
 *  in contains interleaved blocks
 */
void AES_CBC_Encrypt_One(const unsigned char *in,
		     unsigned char *out,
		     const unsigned char ivec1[16],
		     const unsigned long length,
		     const unsigned char *key,
		     const int nr) {
	__m128i feedback1;
	__m128i data1;

	feedback1 = _mm_loadu_si128((__m128i*)ivec1);

	for(int block = 0; block < length / 16; block++) {
		data1 = _mm_loadu_si128(&((__m128i*)in)[block]);

		feedback1 = _mm_xor_si128(data1, feedback1);

		feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);

		int j = 1;
		for(; j < nr; j++) {
			feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
		}

		feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);

		_mm_storeu_si128(&((__m128i*)out)[block], feedback1);

	}
}

void AES_CBC_Encrypt_Two(const unsigned char *in,
                     unsigned char *out,
                     const unsigned char ivec1[16],
		     const unsigned char ivec2[16],
                     const unsigned long length,
                     const unsigned char *key,
                     const int nr) {
        __m128i feedback1;
	__m128i feedback2;

        __m128i data1;
	__m128i data2;

        feedback1 = _mm_loadu_si128((__m128i*)ivec1);
	feedback2 = _mm_loadu_si128((__m128i*)ivec2);

        for(int block = 0; block < length / (16 * 2); block++) {

                data1 = _mm_loadu_si128(&((__m128i*)in)[block * 2 + 0]);
		data2 = _mm_loadu_si128(&((__m128i*)in)[block * 2 + 1]);

                feedback1 = _mm_xor_si128(data1, feedback1);
		feedback2 = _mm_xor_si128(data2, feedback2);

                feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);
		feedback2 = _mm_xor_si128(feedback2, ((__m128i*)key)[0]);

                int j = 1;
                for(; j < nr; j++) {
                        feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
			feedback2 = _mm_aesenc_si128(feedback2, ((__m128i*)key)[j]);
                }

                feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);
	        feedback2 = _mm_aesenclast_si128(feedback2, ((__m128i*)key)[j]);

                _mm_storeu_si128(&((__m128i*)out)[block * 2 + 0], feedback1);
		_mm_storeu_si128(&((__m128i*)out)[block * 2 + 1], feedback2);

        }
}

void AES_CBC_Encrypt_Four(const unsigned char *in,
                     unsigned char *out,
                     const unsigned char ivec1[16],
		     const unsigned char ivec2[16],
		     const unsigned char ivec3[16],
		     const unsigned char ivec4[16],
                     const unsigned long length,
                     const unsigned char *key,
                     const int nr) {
        __m128i feedback1;
	__m128i feedback2;
	__m128i feedback3;
	__m128i feedback4;

        __m128i data1;
	__m128i data2;
	__m128i data3;
	__m128i data4;

        feedback1 = _mm_loadu_si128((__m128i*)ivec1);
	feedback2 = _mm_loadu_si128((__m128i*)ivec2);
	feedback3 = _mm_loadu_si128((__m128i*)ivec3);
	feedback4 = _mm_loadu_si128((__m128i*)ivec4);

        for(int block = 0; block < length / (16 * 4); block++) {

                data1 = _mm_loadu_si128(&((__m128i*)in)[block * 4 + 0]);
		data2 = _mm_loadu_si128(&((__m128i*)in)[block * 4 + 1]);
		data3 = _mm_loadu_si128(&((__m128i*)in)[block * 4 + 2]);
		data4 = _mm_loadu_si128(&((__m128i*)in)[block * 4 + 3]);

                feedback1 = _mm_xor_si128(data1, feedback1);
		feedback2 = _mm_xor_si128(data2, feedback2);
		feedback3 = _mm_xor_si128(data3, feedback3);
		feedback4 = _mm_xor_si128(data4, feedback4);

                feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);
		feedback2 = _mm_xor_si128(feedback2, ((__m128i*)key)[0]);
		feedback3 = _mm_xor_si128(feedback3, ((__m128i*)key)[0]);
		feedback4 = _mm_xor_si128(feedback4, ((__m128i*)key)[0]);

                int j = 1;
                for(; j < nr; j++) {
                        feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
			feedback2 = _mm_aesenc_si128(feedback2, ((__m128i*)key)[j]);
			feedback3 = _mm_aesenc_si128(feedback3, ((__m128i*)key)[j]);
			feedback4 = _mm_aesenc_si128(feedback4, ((__m128i*)key)[j]);
                }

                feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);
	        feedback2 = _mm_aesenclast_si128(feedback2, ((__m128i*)key)[j]);
	        feedback3 = _mm_aesenclast_si128(feedback3, ((__m128i*)key)[j]);
	        feedback4 = _mm_aesenclast_si128(feedback4, ((__m128i*)key)[j]);

                _mm_storeu_si128(&((__m128i*)out)[block * 4 + 0], feedback1);
		_mm_storeu_si128(&((__m128i*)out)[block * 4 + 1], feedback2);
		_mm_storeu_si128(&((__m128i*)out)[block * 4 + 2], feedback3);
		_mm_storeu_si128(&((__m128i*)out)[block * 4 + 3], feedback4);

        }
}

void AES_CBC_Encrypt_Eight(const unsigned char *in,
                     unsigned char *out,
                     const unsigned char ivec1[16],
		     const unsigned char ivec2[16],
		     const unsigned char ivec3[16],
		     const unsigned char ivec4[16],
		     const unsigned char ivec5[16],
		     const unsigned char ivec6[16],
		     const unsigned char ivec7[16],
		     const unsigned char ivec8[16],
                     const unsigned long length,
                     const unsigned char *key,
                     const int nr) {
        __m128i feedback1;
	__m128i feedback2;
	__m128i feedback3;
	__m128i feedback4;
	__m128i feedback5;
	__m128i feedback6;
	__m128i feedback7;
	__m128i feedback8;

        __m128i data1;
	__m128i data2;
	__m128i data3;
	__m128i data4;
	__m128i data5;
	__m128i data6;
	__m128i data7;
	__m128i data8;

        feedback1 = _mm_loadu_si128((__m128i*)ivec1);
	feedback2 = _mm_loadu_si128((__m128i*)ivec2);
	feedback3 = _mm_loadu_si128((__m128i*)ivec3);
	feedback4 = _mm_loadu_si128((__m128i*)ivec4);
	feedback5 = _mm_loadu_si128((__m128i*)ivec5);
	feedback6 = _mm_loadu_si128((__m128i*)ivec6);
	feedback7 = _mm_loadu_si128((__m128i*)ivec7);
	feedback8 = _mm_loadu_si128((__m128i*)ivec8);

        for(int block = 0; block < length / (16 * 8); block++) {

                data1 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 0]);
		data2 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 1]);
		data3 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 2]);
		data4 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 3]);
		data5 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 4]);
		data6 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 5]);
		data7 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 6]);
		data8 = _mm_loadu_si128(&((__m128i*)in)[block * 8 + 7]);

                feedback1 = _mm_xor_si128(data1, feedback1);
		feedback2 = _mm_xor_si128(data2, feedback2);
		feedback3 = _mm_xor_si128(data3, feedback3);
		feedback4 = _mm_xor_si128(data4, feedback4);
		feedback5 = _mm_xor_si128(data5, feedback5);
		feedback6 = _mm_xor_si128(data6, feedback6);
		feedback7 = _mm_xor_si128(data7, feedback7);
		feedback8 = _mm_xor_si128(data8, feedback8);

                feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);
		feedback2 = _mm_xor_si128(feedback2, ((__m128i*)key)[0]);
		feedback3 = _mm_xor_si128(feedback3, ((__m128i*)key)[0]);
		feedback4 = _mm_xor_si128(feedback4, ((__m128i*)key)[0]);
		feedback5 = _mm_xor_si128(feedback5, ((__m128i*)key)[0]);
		feedback6 = _mm_xor_si128(feedback6, ((__m128i*)key)[0]);
		feedback7 = _mm_xor_si128(feedback7, ((__m128i*)key)[0]);
		feedback8 = _mm_xor_si128(feedback8, ((__m128i*)key)[0]);

                int j = 1;
                for(; j < nr; j++) {
                        feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
			feedback2 = _mm_aesenc_si128(feedback2, ((__m128i*)key)[j]);
			feedback3 = _mm_aesenc_si128(feedback3, ((__m128i*)key)[j]);
			feedback4 = _mm_aesenc_si128(feedback4, ((__m128i*)key)[j]);
			feedback5 = _mm_aesenc_si128(feedback5, ((__m128i*)key)[j]);
			feedback6 = _mm_aesenc_si128(feedback6, ((__m128i*)key)[j]);
			feedback7 = _mm_aesenc_si128(feedback7, ((__m128i*)key)[j]);
			feedback8 = _mm_aesenc_si128(feedback8, ((__m128i*)key)[j]);
                }

                feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);
	        feedback2 = _mm_aesenclast_si128(feedback2, ((__m128i*)key)[j]);
	        feedback3 = _mm_aesenclast_si128(feedback3, ((__m128i*)key)[j]);
	        feedback4 = _mm_aesenclast_si128(feedback4, ((__m128i*)key)[j]);
	        feedback5 = _mm_aesenclast_si128(feedback5, ((__m128i*)key)[j]);
	        feedback6 = _mm_aesenclast_si128(feedback6, ((__m128i*)key)[j]);
	        feedback7 = _mm_aesenclast_si128(feedback7, ((__m128i*)key)[j]);
	        feedback8 = _mm_aesenclast_si128(feedback8, ((__m128i*)key)[j]);

                _mm_storeu_si128(&((__m128i*)out)[block * 8 + 0], feedback1);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 1], feedback2);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 2], feedback3);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 3], feedback4);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 4], feedback5);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 5], feedback6);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 6], feedback7);
		_mm_storeu_si128(&((__m128i*)out)[block * 8 + 7], feedback8);

        }
}

void AES_CBC_Encrypt_Sixteen(const unsigned char *in,
                     unsigned char *out,
                     const unsigned char ivec1[16],
		     const unsigned char ivec2[16],
		     const unsigned char ivec3[16],
		     const unsigned char ivec4[16],
		     const unsigned char ivec5[16],
		     const unsigned char ivec6[16],
		     const unsigned char ivec7[16],
		     const unsigned char ivec8[16],
		     const unsigned char ivec9[16],
		     const unsigned char ivec10[16],
		     const unsigned char ivec11[16],
		     const unsigned char ivec12[16],
		     const unsigned char ivec13[16],
		     const unsigned char ivec14[16],
		     const unsigned char ivec15[16],
		     const unsigned char ivec16[16],
                     const unsigned long length,
                     const unsigned char *key,
                     const int nr) {
        __m128i feedback1;
	__m128i feedback2;
	__m128i feedback3;
	__m128i feedback4;
	__m128i feedback5;
	__m128i feedback6;
	__m128i feedback7;
	__m128i feedback8;
	__m128i feedback9;
	__m128i feedback10;
	__m128i feedback11;
	__m128i feedback12;
	__m128i feedback13;
	__m128i feedback14;
	__m128i feedback15;
	__m128i feedback16;

        __m128i data1;
	__m128i data2;
	__m128i data3;
	__m128i data4;
	__m128i data5;
	__m128i data6;
	__m128i data7;
	__m128i data8;
	__m128i data9;
	__m128i data10;
	__m128i data11;
	__m128i data12;
	__m128i data13;
	__m128i data14;
	__m128i data15;
	__m128i data16;

        feedback1 = _mm_loadu_si128((__m128i*)ivec1);
	feedback2 = _mm_loadu_si128((__m128i*)ivec2);
	feedback3 = _mm_loadu_si128((__m128i*)ivec3);
	feedback4 = _mm_loadu_si128((__m128i*)ivec4);
	feedback5 = _mm_loadu_si128((__m128i*)ivec5);
	feedback6 = _mm_loadu_si128((__m128i*)ivec6);
	feedback7 = _mm_loadu_si128((__m128i*)ivec7);
	feedback8 = _mm_loadu_si128((__m128i*)ivec8);
	feedback9 = _mm_loadu_si128((__m128i*)ivec9);
	feedback10 = _mm_loadu_si128((__m128i*)ivec10);
	feedback11 = _mm_loadu_si128((__m128i*)ivec11);
	feedback12 = _mm_loadu_si128((__m128i*)ivec12);
	feedback13 = _mm_loadu_si128((__m128i*)ivec13);
	feedback14 = _mm_loadu_si128((__m128i*)ivec14);
	feedback15 = _mm_loadu_si128((__m128i*)ivec15);
	feedback16 = _mm_loadu_si128((__m128i*)ivec16);

        for(int block = 0; block < length / (16 * 16); block++) {

                data1 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 0]);
		data2 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 1]);
		data3 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 2]);
		data4 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 3]);
		data5 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 4]);
		data6 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 5]);
		data7 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 6]);
		data8 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 7]);
		data9 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 8]);
		data10 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 9]);
		data11 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 10]);
		data12 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 11]);
		data13 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 12]);
		data14 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 13]);
		data15 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 14]);
		data16 = _mm_loadu_si128(&((__m128i*)in)[block * 16 + 15]);

                feedback1 = _mm_xor_si128(data1, feedback1);
		feedback2 = _mm_xor_si128(data2, feedback2);
		feedback3 = _mm_xor_si128(data3, feedback3);
		feedback4 = _mm_xor_si128(data4, feedback4);
		feedback5 = _mm_xor_si128(data5, feedback5);
		feedback6 = _mm_xor_si128(data6, feedback6);
		feedback7 = _mm_xor_si128(data7, feedback7);
		feedback8 = _mm_xor_si128(data8, feedback8);
		feedback9 = _mm_xor_si128(data9, feedback9);
		feedback10 = _mm_xor_si128(data10, feedback10);
		feedback11 = _mm_xor_si128(data11, feedback11);
		feedback12 = _mm_xor_si128(data12, feedback12);
		feedback13 = _mm_xor_si128(data13, feedback13);
		feedback14 = _mm_xor_si128(data14, feedback14);
		feedback15 = _mm_xor_si128(data15, feedback15);
		feedback16 = _mm_xor_si128(data16, feedback16);

                feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);
		feedback2 = _mm_xor_si128(feedback2, ((__m128i*)key)[0]);
		feedback3 = _mm_xor_si128(feedback3, ((__m128i*)key)[0]);
		feedback4 = _mm_xor_si128(feedback4, ((__m128i*)key)[0]);
		feedback5 = _mm_xor_si128(feedback5, ((__m128i*)key)[0]);
		feedback6 = _mm_xor_si128(feedback6, ((__m128i*)key)[0]);
		feedback7 = _mm_xor_si128(feedback7, ((__m128i*)key)[0]);
		feedback8 = _mm_xor_si128(feedback8, ((__m128i*)key)[0]);
		feedback9 = _mm_xor_si128(feedback9, ((__m128i*)key)[0]);
		feedback10 = _mm_xor_si128(feedback10, ((__m128i*)key)[0]);
		feedback11 = _mm_xor_si128(feedback11, ((__m128i*)key)[0]);
		feedback12 = _mm_xor_si128(feedback12, ((__m128i*)key)[0]);
		feedback13 = _mm_xor_si128(feedback13, ((__m128i*)key)[0]);
		feedback14 = _mm_xor_si128(feedback14, ((__m128i*)key)[0]);
		feedback15 = _mm_xor_si128(feedback15, ((__m128i*)key)[0]);
		feedback16 = _mm_xor_si128(feedback16, ((__m128i*)key)[0]);

                int j = 1;
                for(; j < nr; j++) {
                        feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
			feedback2 = _mm_aesenc_si128(feedback2, ((__m128i*)key)[j]);
			feedback3 = _mm_aesenc_si128(feedback3, ((__m128i*)key)[j]);
			feedback4 = _mm_aesenc_si128(feedback4, ((__m128i*)key)[j]);
			feedback5 = _mm_aesenc_si128(feedback5, ((__m128i*)key)[j]);
			feedback6 = _mm_aesenc_si128(feedback6, ((__m128i*)key)[j]);
			feedback7 = _mm_aesenc_si128(feedback7, ((__m128i*)key)[j]);
			feedback8 = _mm_aesenc_si128(feedback8, ((__m128i*)key)[j]);
			feedback9 = _mm_aesenc_si128(feedback9, ((__m128i*)key)[j]);
			feedback10 = _mm_aesenc_si128(feedback10, ((__m128i*)key)[j]);
			feedback11 = _mm_aesenc_si128(feedback11, ((__m128i*)key)[j]);
			feedback12 = _mm_aesenc_si128(feedback12, ((__m128i*)key)[j]);
			feedback13 = _mm_aesenc_si128(feedback13, ((__m128i*)key)[j]);
			feedback14 = _mm_aesenc_si128(feedback14, ((__m128i*)key)[j]);
			feedback15 = _mm_aesenc_si128(feedback15, ((__m128i*)key)[j]);
			feedback16 = _mm_aesenc_si128(feedback16, ((__m128i*)key)[j]);
                }

                feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);
	        feedback2 = _mm_aesenclast_si128(feedback2, ((__m128i*)key)[j]);
	        feedback3 = _mm_aesenclast_si128(feedback3, ((__m128i*)key)[j]);
	        feedback4 = _mm_aesenclast_si128(feedback4, ((__m128i*)key)[j]);
	        feedback5 = _mm_aesenclast_si128(feedback5, ((__m128i*)key)[j]);
	        feedback6 = _mm_aesenclast_si128(feedback6, ((__m128i*)key)[j]);
	        feedback7 = _mm_aesenclast_si128(feedback7, ((__m128i*)key)[j]);
	        feedback8 = _mm_aesenclast_si128(feedback8, ((__m128i*)key)[j]);
	        feedback9 = _mm_aesenclast_si128(feedback9, ((__m128i*)key)[j]);
	        feedback10 = _mm_aesenclast_si128(feedback10, ((__m128i*)key)[j]);
	        feedback11 = _mm_aesenclast_si128(feedback11, ((__m128i*)key)[j]);
	        feedback12 = _mm_aesenclast_si128(feedback12, ((__m128i*)key)[j]);
	        feedback13 = _mm_aesenclast_si128(feedback13, ((__m128i*)key)[j]);
	        feedback14 = _mm_aesenclast_si128(feedback14, ((__m128i*)key)[j]);
	        feedback15 = _mm_aesenclast_si128(feedback15, ((__m128i*)key)[j]);
	        feedback16 = _mm_aesenclast_si128(feedback16, ((__m128i*)key)[j]);

                _mm_storeu_si128(&((__m128i*)out)[block * 16 + 0], feedback1);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 1], feedback2);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 2], feedback3);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 3], feedback4);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 4], feedback5);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 5], feedback6);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 6], feedback7);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 7], feedback8);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 8], feedback9);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 9], feedback10);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 10], feedback11);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 11], feedback12);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 12], feedback13);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 13], feedback14);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 14], feedback15);
		_mm_storeu_si128(&((__m128i*)out)[block * 16 + 15], feedback16);

        }
}

void AES_CBC_Encrypt_ThirtyTwo(const unsigned char *in,
                     unsigned char *out,
                     const unsigned char ivec1[16],
		     const unsigned char ivec2[16],
		     const unsigned char ivec3[16],
		     const unsigned char ivec4[16],
		     const unsigned char ivec5[16],
		     const unsigned char ivec6[16],
		     const unsigned char ivec7[16],
		     const unsigned char ivec8[16],
		     const unsigned char ivec9[16],
		     const unsigned char ivec10[16],
		     const unsigned char ivec11[16],
		     const unsigned char ivec12[16],
		     const unsigned char ivec13[16],
		     const unsigned char ivec14[16],
		     const unsigned char ivec15[16],
		     const unsigned char ivec16[16],
		     const unsigned char ivec17[16],
		     const unsigned char ivec18[16],
		     const unsigned char ivec19[16],
		     const unsigned char ivec20[16],
		     const unsigned char ivec21[16],
		     const unsigned char ivec22[16],
		     const unsigned char ivec23[16],
		     const unsigned char ivec24[16],
		     const unsigned char ivec25[16],
		     const unsigned char ivec26[16],
		     const unsigned char ivec27[16],
		     const unsigned char ivec28[16],
		     const unsigned char ivec29[16],
		     const unsigned char ivec30[16],
		     const unsigned char ivec31[16],
		     const unsigned char ivec32[16],
                     const unsigned long length,
                     const unsigned char *key,
                     const int nr) {
        __m128i feedback1;
	__m128i feedback2;
	__m128i feedback3;
	__m128i feedback4;
	__m128i feedback5;
	__m128i feedback6;
	__m128i feedback7;
	__m128i feedback8;
	__m128i feedback9;
	__m128i feedback10;
	__m128i feedback11;
	__m128i feedback12;
	__m128i feedback13;
	__m128i feedback14;
	__m128i feedback15;
	__m128i feedback16;
	__m128i feedback17;
	__m128i feedback18;
	__m128i feedback19;
	__m128i feedback20;
	__m128i feedback21;
	__m128i feedback22;
	__m128i feedback23;
	__m128i feedback24;
	__m128i feedback25;
	__m128i feedback26;
	__m128i feedback27;
	__m128i feedback28;
	__m128i feedback29;
	__m128i feedback30;
	__m128i feedback31;
	__m128i feedback32;

        __m128i data1;
	__m128i data2;
	__m128i data3;
	__m128i data4;
	__m128i data5;
	__m128i data6;
	__m128i data7;
	__m128i data8;
	__m128i data9;
	__m128i data10;
	__m128i data11;
	__m128i data12;
	__m128i data13;
	__m128i data14;
	__m128i data15;
	__m128i data16;
	__m128i data17;
	__m128i data18;
	__m128i data19;
	__m128i data20;
	__m128i data21;
	__m128i data22;
	__m128i data23;
	__m128i data24;
	__m128i data25;
	__m128i data26;
	__m128i data27;
	__m128i data28;
	__m128i data29;
	__m128i data30;
	__m128i data31;
	__m128i data32;

        feedback1 = _mm_loadu_si128((__m128i*)ivec1);
	feedback2 = _mm_loadu_si128((__m128i*)ivec2);
	feedback3 = _mm_loadu_si128((__m128i*)ivec3);
	feedback4 = _mm_loadu_si128((__m128i*)ivec4);
	feedback5 = _mm_loadu_si128((__m128i*)ivec5);
	feedback6 = _mm_loadu_si128((__m128i*)ivec6);
	feedback7 = _mm_loadu_si128((__m128i*)ivec7);
	feedback8 = _mm_loadu_si128((__m128i*)ivec8);
	feedback9 = _mm_loadu_si128((__m128i*)ivec9);
	feedback10 = _mm_loadu_si128((__m128i*)ivec10);
	feedback11 = _mm_loadu_si128((__m128i*)ivec11);
	feedback12 = _mm_loadu_si128((__m128i*)ivec12);
	feedback13 = _mm_loadu_si128((__m128i*)ivec13);
	feedback14 = _mm_loadu_si128((__m128i*)ivec14);
	feedback15 = _mm_loadu_si128((__m128i*)ivec15);
	feedback16 = _mm_loadu_si128((__m128i*)ivec16);
	feedback17 = _mm_loadu_si128((__m128i*)ivec17);
	feedback18 = _mm_loadu_si128((__m128i*)ivec18);
	feedback19 = _mm_loadu_si128((__m128i*)ivec19);
	feedback20 = _mm_loadu_si128((__m128i*)ivec20);
	feedback21 = _mm_loadu_si128((__m128i*)ivec21);
	feedback22 = _mm_loadu_si128((__m128i*)ivec22);
	feedback23 = _mm_loadu_si128((__m128i*)ivec23);
	feedback24 = _mm_loadu_si128((__m128i*)ivec24);
	feedback25 = _mm_loadu_si128((__m128i*)ivec25);
	feedback26 = _mm_loadu_si128((__m128i*)ivec26);
	feedback27 = _mm_loadu_si128((__m128i*)ivec27);
	feedback28 = _mm_loadu_si128((__m128i*)ivec28);
	feedback29 = _mm_loadu_si128((__m128i*)ivec29);
	feedback30 = _mm_loadu_si128((__m128i*)ivec30);
	feedback31 = _mm_loadu_si128((__m128i*)ivec31);
	feedback32 = _mm_loadu_si128((__m128i*)ivec32);

        for(int block = 0; block < length / (16 * 32); block++) {

                data1 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 0]);
		data2 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 1]);
		data3 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 2]);
		data4 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 3]);
		data5 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 4]);
		data6 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 5]);
		data7 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 6]);
		data8 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 7]);
		data9 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 8]);
		data10 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 9]);
		data11 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 10]);
		data12 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 11]);
		data13 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 12]);
		data14 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 13]);
		data15 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 14]);
		data16 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 15]);
		data17 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 16]);
		data18 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 17]);
		data19 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 18]);
		data20 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 19]);
		data21 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 20]);
		data22 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 21]);
		data23 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 22]);
		data24 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 23]);
		data25 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 24]);
		data26 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 25]);
		data27 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 26]);
		data28 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 27]);
		data29 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 28]);
		data30 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 29]);
		data31 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 30]);
		data32 = _mm_loadu_si128(&((__m128i*)in)[block * 32 + 31]);

                feedback1 = _mm_xor_si128(data1, feedback1);
		feedback2 = _mm_xor_si128(data2, feedback2);
		feedback3 = _mm_xor_si128(data3, feedback3);
		feedback4 = _mm_xor_si128(data4, feedback4);
		feedback5 = _mm_xor_si128(data5, feedback5);
		feedback6 = _mm_xor_si128(data6, feedback6);
		feedback7 = _mm_xor_si128(data7, feedback7);
		feedback8 = _mm_xor_si128(data8, feedback8);
		feedback9 = _mm_xor_si128(data9, feedback9);
		feedback10 = _mm_xor_si128(data10, feedback10);
		feedback11 = _mm_xor_si128(data11, feedback11);
		feedback12 = _mm_xor_si128(data12, feedback12);
		feedback13 = _mm_xor_si128(data13, feedback13);
		feedback14 = _mm_xor_si128(data14, feedback14);
		feedback15 = _mm_xor_si128(data15, feedback15);
		feedback16 = _mm_xor_si128(data16, feedback16);
		feedback17 = _mm_xor_si128(data17, feedback17);
		feedback18 = _mm_xor_si128(data18, feedback18);
		feedback19 = _mm_xor_si128(data19, feedback19);
		feedback20 = _mm_xor_si128(data20, feedback20);
		feedback21 = _mm_xor_si128(data21, feedback21);
		feedback22 = _mm_xor_si128(data22, feedback22);
		feedback23 = _mm_xor_si128(data23, feedback23);
		feedback24 = _mm_xor_si128(data24, feedback24);
		feedback25 = _mm_xor_si128(data25, feedback25);
		feedback26 = _mm_xor_si128(data26, feedback26);
		feedback27 = _mm_xor_si128(data27, feedback27);
		feedback28 = _mm_xor_si128(data28, feedback28);
		feedback29 = _mm_xor_si128(data29, feedback29);
		feedback30 = _mm_xor_si128(data30, feedback30);
		feedback31 = _mm_xor_si128(data31, feedback31);
		feedback32 = _mm_xor_si128(data32, feedback32);

                feedback1 = _mm_xor_si128(feedback1, ((__m128i*)key)[0]);
		feedback2 = _mm_xor_si128(feedback2, ((__m128i*)key)[0]);
		feedback3 = _mm_xor_si128(feedback3, ((__m128i*)key)[0]);
		feedback4 = _mm_xor_si128(feedback4, ((__m128i*)key)[0]);
		feedback5 = _mm_xor_si128(feedback5, ((__m128i*)key)[0]);
		feedback6 = _mm_xor_si128(feedback6, ((__m128i*)key)[0]);
		feedback7 = _mm_xor_si128(feedback7, ((__m128i*)key)[0]);
		feedback8 = _mm_xor_si128(feedback8, ((__m128i*)key)[0]);
		feedback9 = _mm_xor_si128(feedback9, ((__m128i*)key)[0]);
		feedback10 = _mm_xor_si128(feedback10, ((__m128i*)key)[0]);
		feedback11 = _mm_xor_si128(feedback11, ((__m128i*)key)[0]);
		feedback12 = _mm_xor_si128(feedback12, ((__m128i*)key)[0]);
		feedback13 = _mm_xor_si128(feedback13, ((__m128i*)key)[0]);
		feedback14 = _mm_xor_si128(feedback14, ((__m128i*)key)[0]);
		feedback15 = _mm_xor_si128(feedback15, ((__m128i*)key)[0]);
		feedback16 = _mm_xor_si128(feedback16, ((__m128i*)key)[0]);
		feedback17 = _mm_xor_si128(feedback17, ((__m128i*)key)[0]);
		feedback18 = _mm_xor_si128(feedback18, ((__m128i*)key)[0]);
		feedback19 = _mm_xor_si128(feedback19, ((__m128i*)key)[0]);
		feedback20 = _mm_xor_si128(feedback20, ((__m128i*)key)[0]);
		feedback21 = _mm_xor_si128(feedback21, ((__m128i*)key)[0]);
		feedback22 = _mm_xor_si128(feedback22, ((__m128i*)key)[0]);
		feedback23 = _mm_xor_si128(feedback23, ((__m128i*)key)[0]);
		feedback24 = _mm_xor_si128(feedback24, ((__m128i*)key)[0]);
		feedback25 = _mm_xor_si128(feedback25, ((__m128i*)key)[0]);
		feedback26 = _mm_xor_si128(feedback26, ((__m128i*)key)[0]);
		feedback27 = _mm_xor_si128(feedback27, ((__m128i*)key)[0]);
		feedback28 = _mm_xor_si128(feedback28, ((__m128i*)key)[0]);
		feedback29 = _mm_xor_si128(feedback29, ((__m128i*)key)[0]);
		feedback30 = _mm_xor_si128(feedback30, ((__m128i*)key)[0]);
		feedback31 = _mm_xor_si128(feedback31, ((__m128i*)key)[0]);
		feedback32 = _mm_xor_si128(feedback32, ((__m128i*)key)[0]);

                int j = 1;
                for(; j < nr; j++) {
                        feedback1 = _mm_aesenc_si128(feedback1, ((__m128i*)key)[j]);
			feedback2 = _mm_aesenc_si128(feedback2, ((__m128i*)key)[j]);
			feedback3 = _mm_aesenc_si128(feedback3, ((__m128i*)key)[j]);
			feedback4 = _mm_aesenc_si128(feedback4, ((__m128i*)key)[j]);
			feedback5 = _mm_aesenc_si128(feedback5, ((__m128i*)key)[j]);
			feedback6 = _mm_aesenc_si128(feedback6, ((__m128i*)key)[j]);
			feedback7 = _mm_aesenc_si128(feedback7, ((__m128i*)key)[j]);
			feedback8 = _mm_aesenc_si128(feedback8, ((__m128i*)key)[j]);
			feedback9 = _mm_aesenc_si128(feedback9, ((__m128i*)key)[j]);
			feedback10 = _mm_aesenc_si128(feedback10, ((__m128i*)key)[j]);
			feedback11 = _mm_aesenc_si128(feedback11, ((__m128i*)key)[j]);
			feedback12 = _mm_aesenc_si128(feedback12, ((__m128i*)key)[j]);
			feedback13 = _mm_aesenc_si128(feedback13, ((__m128i*)key)[j]);
			feedback14 = _mm_aesenc_si128(feedback14, ((__m128i*)key)[j]);
			feedback15 = _mm_aesenc_si128(feedback15, ((__m128i*)key)[j]);
			feedback16 = _mm_aesenc_si128(feedback16, ((__m128i*)key)[j]);
			feedback17 = _mm_aesenc_si128(feedback17, ((__m128i*)key)[j]);
			feedback18 = _mm_aesenc_si128(feedback18, ((__m128i*)key)[j]);
			feedback19 = _mm_aesenc_si128(feedback19, ((__m128i*)key)[j]);
			feedback20 = _mm_aesenc_si128(feedback20, ((__m128i*)key)[j]);
			feedback21 = _mm_aesenc_si128(feedback21, ((__m128i*)key)[j]);
			feedback22 = _mm_aesenc_si128(feedback22, ((__m128i*)key)[j]);
			feedback23 = _mm_aesenc_si128(feedback23, ((__m128i*)key)[j]);
			feedback24 = _mm_aesenc_si128(feedback24, ((__m128i*)key)[j]);
			feedback25 = _mm_aesenc_si128(feedback25, ((__m128i*)key)[j]);
			feedback26 = _mm_aesenc_si128(feedback26, ((__m128i*)key)[j]);
			feedback27 = _mm_aesenc_si128(feedback27, ((__m128i*)key)[j]);
			feedback28 = _mm_aesenc_si128(feedback28, ((__m128i*)key)[j]);
			feedback29 = _mm_aesenc_si128(feedback29, ((__m128i*)key)[j]);
			feedback30 = _mm_aesenc_si128(feedback30, ((__m128i*)key)[j]);
			feedback31 = _mm_aesenc_si128(feedback31, ((__m128i*)key)[j]);
			feedback32 = _mm_aesenc_si128(feedback32, ((__m128i*)key)[j]);
                }

                feedback1 = _mm_aesenclast_si128(feedback1, ((__m128i*)key)[j]);
	        feedback2 = _mm_aesenclast_si128(feedback2, ((__m128i*)key)[j]);
	        feedback3 = _mm_aesenclast_si128(feedback3, ((__m128i*)key)[j]);
	        feedback4 = _mm_aesenclast_si128(feedback4, ((__m128i*)key)[j]);
	        feedback5 = _mm_aesenclast_si128(feedback5, ((__m128i*)key)[j]);
	        feedback6 = _mm_aesenclast_si128(feedback6, ((__m128i*)key)[j]);
	        feedback7 = _mm_aesenclast_si128(feedback7, ((__m128i*)key)[j]);
	        feedback8 = _mm_aesenclast_si128(feedback8, ((__m128i*)key)[j]);
	        feedback9 = _mm_aesenclast_si128(feedback9, ((__m128i*)key)[j]);
	        feedback10 = _mm_aesenclast_si128(feedback10, ((__m128i*)key)[j]);
	        feedback11 = _mm_aesenclast_si128(feedback11, ((__m128i*)key)[j]);
	        feedback12 = _mm_aesenclast_si128(feedback12, ((__m128i*)key)[j]);
	        feedback13 = _mm_aesenclast_si128(feedback13, ((__m128i*)key)[j]);
	        feedback14 = _mm_aesenclast_si128(feedback14, ((__m128i*)key)[j]);
	        feedback15 = _mm_aesenclast_si128(feedback15, ((__m128i*)key)[j]);
	        feedback16 = _mm_aesenclast_si128(feedback16, ((__m128i*)key)[j]);
	        feedback17 = _mm_aesenclast_si128(feedback17, ((__m128i*)key)[j]);
	        feedback18 = _mm_aesenclast_si128(feedback18, ((__m128i*)key)[j]);
	        feedback19 = _mm_aesenclast_si128(feedback19, ((__m128i*)key)[j]);
	        feedback20 = _mm_aesenclast_si128(feedback20, ((__m128i*)key)[j]);
	        feedback21 = _mm_aesenclast_si128(feedback21, ((__m128i*)key)[j]);
	        feedback22 = _mm_aesenclast_si128(feedback22, ((__m128i*)key)[j]);
	        feedback23 = _mm_aesenclast_si128(feedback23, ((__m128i*)key)[j]);
	        feedback24 = _mm_aesenclast_si128(feedback24, ((__m128i*)key)[j]);
	        feedback25 = _mm_aesenclast_si128(feedback25, ((__m128i*)key)[j]);
	        feedback26 = _mm_aesenclast_si128(feedback26, ((__m128i*)key)[j]);
	        feedback27 = _mm_aesenclast_si128(feedback27, ((__m128i*)key)[j]);
	        feedback28 = _mm_aesenclast_si128(feedback28, ((__m128i*)key)[j]);
	        feedback29 = _mm_aesenclast_si128(feedback29, ((__m128i*)key)[j]);
	        feedback30 = _mm_aesenclast_si128(feedback30, ((__m128i*)key)[j]);
	        feedback31 = _mm_aesenclast_si128(feedback31, ((__m128i*)key)[j]);
	        feedback32 = _mm_aesenclast_si128(feedback32, ((__m128i*)key)[j]);

                _mm_storeu_si128(&((__m128i*)out)[block * 32 + 0], feedback1);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 1], feedback2);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 2], feedback3);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 3], feedback4);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 4], feedback5);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 5], feedback6);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 6], feedback7);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 7], feedback8);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 8], feedback9);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 9], feedback10);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 10], feedback11);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 11], feedback12);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 12], feedback13);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 13], feedback14);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 14], feedback15);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 15], feedback16);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 16], feedback17);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 17], feedback18);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 18], feedback19);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 19], feedback20);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 20], feedback21);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 21], feedback22);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 22], feedback23);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 23], feedback24);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 24], feedback25);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 25], feedback26);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 26], feedback27);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 27], feedback28);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 28], feedback29);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 29], feedback30);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 30], feedback31);
		_mm_storeu_si128(&((__m128i*)out)[block * 32 + 31], feedback32);

        }
}


int main() {

        const uint32_t width = 1;

        const unsigned char key[16] = {
		0xc2, 0x86, 0x69, 0x6d, 
		0x88, 0x7c, 0x9a, 0xa0, 
		0x61, 0x1b, 0xbb, 0x3e,
		0x20, 0x25, 0xa4, 0x5a
	};

	const unsigned char ivec[16] = {
		0x56, 0x2e, 0x17, 0x99,
		0x6d, 0x09, 0x3d, 0x28,
		0xdd, 0xb3, 0xba, 0x69,
		0x5a, 0x2e, 0x6f, 0x58
	};

        // Generate the key schedule
        unsigned char keyschedule[172];
	AES_128_Key_Expansion(key, keyschedule);

#define USE_RANDOM_DATA 0

#if USE_RANDOM_DATA
	const uint32_t numBytes = 1024 * 1024;
#else
	const uint32_t numBytes = 128;

        const unsigned char plaintextA[128] = {
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
        };

        const unsigned char plaintextB[128] = {
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
        };

#endif

        unsigned char *plaintextInterleaved = (unsigned char *)calloc(width * numBytes, 1);

        for(int block = 0; block < numBytes / 16; block++) {
		memcpy(&plaintextInterleaved[block * numBytes + 0 * 16], plaintextA + block * 16, 16);
		memcpy(&plaintextInterleaved[block * numBytes + 1 * 16], plaintextB + block * 16, 16); 
	}

	unsigned char ciphertextInterleaved[width * numBytes];
	memset(ciphertextInterleaved, 0x00, width * numBytes);

        const uint32_t numTrials = 100000;
	struct timeval start_time, end_time;
	gettimeofday(&start_time, NULL);

	switch(width) {
		case 1: {
		    for(uint32_t trial = 0; trial < numTrials; trial++) {
			AES_CBC_Encrypt_One(plaintextInterleaved, ciphertextInterleaved, ivec, numBytes * width, keyschedule, 10);
		    }
		}
			break;
		case 2: {
                    for(uint32_t trial = 0; trial < numTrials; trial++) {
                        AES_CBC_Encrypt_Two(plaintextInterleaved, ciphertextInterleaved, ivec, ivec, numBytes * width, keyschedule, 10);
                    }
                }
			
			break;
		case 4: {
                    for(uint32_t trial = 0; trial < numTrials; trial++) {
                        AES_CBC_Encrypt_Four(plaintextInterleaved, ciphertextInterleaved, ivec, ivec, ivec, ivec, numBytes * width, keyschedule, 10);
                    }
                }
			
			break;			
		case 8: {
                    for(uint32_t trial = 0; trial < numTrials; trial++) {
                        AES_CBC_Encrypt_Eight(plaintextInterleaved, ciphertextInterleaved, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, numBytes * width, keyschedule, 10);
                    }
                }
			
			break;	
		case 16: {
                    for(uint32_t trial = 0; trial < numTrials; trial++) {
                        AES_CBC_Encrypt_Sixteen(plaintextInterleaved, ciphertextInterleaved, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, numBytes * width, keyschedule, 10);
                    }
                }
			
			break;						
		case 32: {
                    for(uint32_t trial = 0; trial < numTrials; trial++) {
                        AES_CBC_Encrypt_ThirtyTwo(plaintextInterleaved, ciphertextInterleaved, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, ivec, numBytes * width, keyschedule, 10);
                    }
                }
			
			break;				
	}

	gettimeofday(&end_time, NULL);
	int elapsed_microseconds = 1000000 * (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec);

	float time_consumed = (float)elapsed_microseconds;
        fprintf(stderr, "Width: %d. Encrypted at %.2f MB/s\n", width, ((float)(numTrials * numBytes * width)) / (float)time_consumed);

	free(plaintextInterleaved);

	return 0;
}










__m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) { 
    __m128i temp3; 
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff); 
    temp3 = _mm_slli_si128 (temp1, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3);   
    temp1 = _mm_xor_si128 (temp1, temp2); 
    return temp1; 

    } 

void AES_128_Key_Expansion (const unsigned char *userkey,
                            unsigned char *key)
    {
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 =_mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 =_mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 =_mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 =_mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 =_mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 =_mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[6] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[7] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[8] = temp1;     
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[9] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[10] = temp1; 
    }     
