if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120040" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:15:56 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-557)" );
	script_tag( name: "insight", value: "Integer signedness error in the mobility_opt_print function in the IPv6 mobility printer in tcpdump before 4.7.2 allows remote attackers to cause a denial of service (out-of-bounds read and crash) or possibly execute arbitrary code via a negative length value. (CVE-2015-0261 )The osi_print_cksum function in print-isoclns.c in the ethernet printer in tcpdump before 4.7.2 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted (1) length, (2) offset, or (3) base pointer checksum value. (CVE-2015-2154 )" );
	script_tag( name: "solution", value: "Run yum update tcpdump to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-557.html" );
	script_cve_id( "CVE-2015-0261", "CVE-2015-2154" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "tcpdump", rpm: "tcpdump~4.0.0~3.20090921gitdf3cb4.2.10.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcpdump-debuginfo", rpm: "tcpdump-debuginfo~4.0.0~3.20090921gitdf3cb4.2.10.amzn1", rls: "AMAZON" ) )){
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

