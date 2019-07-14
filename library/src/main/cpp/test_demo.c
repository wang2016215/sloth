/**************************************************
* File name: test_demo.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 9th, 2018
* Description: implement test demo program for
    SM2 encrypt data and decrypt ciphertext
**************************************************/

#include "test_sm2_encrypt_and_decrypt.h"
#include "log.h"

/*********************************************************/
int main(void)
{
	int error_code;

	LOGD("TAG","/*********************************************************/\n");
	if ( error_code = test_with_input_defined_in_standard() )
	{
		LOGD("","Test SM2 encrypt data and decrypt ciphertext with input defined in standard failed!\n");
		return error_code;
	}
	else
	{
		LOGD("","Test SM2 encrypt data and decrypt ciphertext with input defined in standard succeeded!\n");
	}

	LOGD("","\n/*********************************************************/\n");
	if ( error_code = test_sm2_encrypt_and_decrypt() )
	{
		LOGD("","Test create SM2 key pair, encrypt data and decrypt ciphertext failed!\n");
		return error_code;
	}
	else
	{
		LOGD("","Test create SM2 key pair, encrypt data and decrypt ciphertext succeeded!\n");
	}

#if defined(_WIN32) || defined(_WIN64)
  system("pause");
#endif
	return 0;
}