if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120373" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:56 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-504)" );
	script_tag( name: "insight", value: "A buffer overflow was found in the way unzip uncompressed certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash or, possibly, execute arbitrary code when the archive was tested with unzip's '-t' option. (CVE-2014-9636 )A buffer overflow flaw was found in the way unzip computed the CRC32 checksum of certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash when the archive was tested with unzip's '-t' option. (CVE-2014-8139 )An integer underflow flaw, leading to a buffer overflow, was found in the way unzip uncompressed certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash when the archive was tested with unzip's '-t' option. (CVE-2014-8140 )A buffer overflow flaw was found in the way unzip handled Zip64 files. A specially crafted Zip archive could possibly cause unzip to crash when the archive was uncompressed. (CVE-2014-8141 )" );
	script_tag( name: "solution", value: "Run yum update unzip to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-504.html" );
	script_cve_id( "CVE-2014-8139", "CVE-2014-8141", "CVE-2014-8140", "CVE-2014-9636" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "unzip-debuginfo", rpm: "unzip-debuginfo~6.0~2.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unzip", rpm: "unzip~6.0~2.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

