if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120486" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:27:34 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-128)" );
	script_tag( name: "insight", value: "It was discovered that the D-Bus library honored environment settings even when running with elevated privileges. A local attacker could possibly use this flaw to escalate their privileges, by setting specific environment variables before running a setuid or setgid application linked against the D-Bus library (libdbus). (CVE-2012-3524 )" );
	script_tag( name: "solution", value: "Run yum update dbus to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-128.html" );
	script_cve_id( "CVE-2012-3524" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "dbus-libs", rpm: "dbus-libs~1.2.24~7.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-debuginfo", rpm: "dbus-debuginfo~1.2.24~7.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus", rpm: "dbus~1.2.24~7.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-doc", rpm: "dbus-doc~1.2.24~7.16.amzn1", rls: "AMAZON" ) )){
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

