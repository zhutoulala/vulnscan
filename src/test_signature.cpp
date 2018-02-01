#include "gtest/gtest.h"
#include "signature.h"

TEST(SignatureLoader, loadSigs)
{
	std::istringstream is("CVE-2017-9502\n\
STRING:\n\
+ expected localhost or 127.0.0.1 or none\n\
ASM:\n\
- parseurlandfillconn strlen strlen strlen curl_strmequal Curl_failf curl_strmequal curl_strmequal Curl_failf Curl_cmalloc\n\
\n\
CVE-2017-1000100\n\
STRING:\n\
+ TFTP: Unknown transfer ID\n\
+ Disk full or allocation exceeded\n\
+ tftp_rx: giving up waiting for block\n\
- TFTP file name too long");

	SignatureLoader loader;
	loader.loadSigs(is);
	EXPECT_EQ(loader.getSize(), 2);
	EXPECT_EQ(loader.getSignature(0)->getCVE(), "CVE-2017-9502");
	EXPECT_EQ(loader.getSignature(1)->getCVE(), "CVE-2017-1000100");

}