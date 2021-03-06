if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120643" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "creation_date", value: "2016-02-17 11:37:59 +0200 (Wed, 17 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-653)" );
	script_tag( name: "insight", value: "A stack-based buffer overflow flaw was found in the send_dg() and send_vc() functions, used by getaddrinfo() and other higher-level interfaces of glibc. A remote attacker able to cause an application to call either of these functions could use this flaw to execute arbitrary code with the permissions of the user running the application." );
	script_tag( name: "solution", value: "Run yum update glibc to update your system.  Note that you may need to run yum clean all first.  Once this update has been applied, reboot your instance to ensure that all processes and daemons that link against glibc are using the updated version.  On new instance launches prior to Amazon Linux AMI 2015.09.2, you should still reboot after cloud-init has automatically applied this update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-653.html" );
	script_cve_id( "CVE-2015-7547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)" );
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
	if(!isnull( res = isrpmvuln( pkg: "glibc-static", rpm: "glibc-static~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo", rpm: "glibc-debuginfo~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo-common", rpm: "glibc-debuginfo-common~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.17~106.166.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.17~106.166.amzn1", rls: "AMAZON" ) )){
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

