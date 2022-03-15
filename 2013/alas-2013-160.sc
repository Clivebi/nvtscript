if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120393" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:25:19 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-160)" );
	script_tag( name: "insight", value: "A stack-based buffer overflow flaw was found in the way the pam_env module parsed users' ~/.pam_environment files. If an application's PAM configuration contained user_readenv=1 (this is not the default), a local attacker could use this flaw to crash the application or, possibly, escalate their privileges. (CVE-2011-3148 )A denial of service flaw was found in the way the pam_env module expanded certain environment variables. If an application's PAM configuration contained user_readenv=1 (this is not the default), a local attacker could use this flaw to cause the application to enter an infinite loop. (CVE-2011-3149 )" );
	script_tag( name: "solution", value: "Run yum update pam to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-160.html" );
	script_cve_id( "CVE-2011-3149", "CVE-2011-3148" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "pam-debuginfo", rpm: "pam-debuginfo~1.1.1~13.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam", rpm: "pam~1.1.1~13.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam-devel", rpm: "pam-devel~1.1.1~13.20.amzn1", rls: "AMAZON" ) )){
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

