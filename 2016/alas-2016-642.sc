if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120632" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "creation_date", value: "2016-01-20 07:22:48 +0200 (Wed, 20 Jan 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-642)" );
	script_tag( name: "insight", value: "Perception Point Research identified a use-after-free vulnerability, representing a local privilege escalation vulnerability in the Linux kernel. Their post contains a detailed analysis of the bug.kernel-4.1.13-19.30.amzn1 and earlier versions are impacted." );
	script_tag( name: "solution", value: "Run yum clean all followed by yum update kernel to update your system. You will need to reboot your system in order for the new kernel to be running." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-642.html" );
	script_cve_id( "CVE-2016-0728" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-10 02:29:00 +0000 (Fri, 10 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-debuginfo", rpm: "kernel-tools-debuginfo~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf-debuginfo", rpm: "perf-debuginfo~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-devel", rpm: "kernel-tools-devel~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo-common-i686", rpm: "kernel-debuginfo-common-i686~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo-common-x86_64", rpm: "kernel-debuginfo-common-x86_64~4.1.13~19.31.amzn1", rls: "AMAZON" ) )){
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

