if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120171" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:19:09 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-497)" );
	script_tag( name: "insight", value: "The ELF parser in file 5.08 through 5.21 allows remote attackers to cause a denial of service via a large number of notes. (CVE-2014-9620 )The ELF parser (readelf.c) in file before 5.21 allows remote attackers to cause a denial of service (CPU consumption or crash) via a large number of (1) program or (2) section headers or (3) invalid capabilities. (CVE-2014-8116 )It was reported that a malformed elf file can cause file urility to access invalid memory. (CVE-2014-9653 )The ELF parser in file 5.16 through 5.21 allows remote attackers to cause a denial of service via a long string. (CVE-2014-9621 )softmagic.c in file before 5.21 does not properly limit recursion, which allows remote attackers to cause a denial of service (CPU consumption or crash) via unspecified vectors. (CVE-2014-8117 )" );
	script_tag( name: "solution", value: "Run yum update file to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-497.html" );
	script_cve_id( "CVE-2014-9620", "CVE-2014-8116", "CVE-2014-9653", "CVE-2014-9621", "CVE-2014-8117" );
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
	if(!isnull( res = isrpmvuln( pkg: "file-debuginfo", rpm: "file-debuginfo~5.22~2.29.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-devel", rpm: "file-devel~5.22~2.29.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-libs", rpm: "file-libs~5.22~2.29.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-static", rpm: "file-static~5.22~2.29.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26-magic", rpm: "python26-magic~5.22~2.29.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27-magic", rpm: "python27-magic~5.22~2.29.amzn1", rls: "AMAZON" ) )){
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

