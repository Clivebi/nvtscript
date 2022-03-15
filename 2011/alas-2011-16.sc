if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120275" );
	script_version( "2021-05-19T13:27:50+0200" );
	script_tag( name: "creation_date", value: "2015-09-08 11:21:32 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2021-05-19 13:27:50 +0200 (Wed, 19 May 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2011-16)" );
	script_tag( name: "insight", value: "Multiple flaws were found in the Linux kernel. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update kernel to update your system. You will need to reboot your system in order for the new kernel to be running." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2011-16.html" );
	script_cve_id( "CVE-2011-2723", "CVE-2011-1833", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-2918" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)" );
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
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo-common-i686", rpm: "kernel-debuginfo-common-i686~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.35.14~97.44.amzn1", rls: "AMAZON" ) )){
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

