if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120574" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:52 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-375)" );
	script_tag( name: "insight", value: "It was found that mod_wsgi did not properly drop privileges if the call to setuid() failed. If mod_wsgi was set up to allow unprivileged users to run WSGI applications, a local user able to run a WSGI application could possibly use this flaw to escalate their privileges on the system. Note: mod_wsgi is not intended to provide privilege separation for WSGI applications. Systems relying on mod_wsgi to limit or sandbox the privileges of mod_wsgi applications should migrate to a different solution with proper privilege separation. mod_wsgi allows you to host Python applications on the Apache HTTP Server. It was found that a remote attacker could leak portions of a mod_wsgi application's memory via the Content-Type header." );
	script_tag( name: "solution", value: "Run yum update mod24_wsgi to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-375.html" );
	script_cve_id( "CVE-2014-0242", "CVE-2014-0240" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "mod24_wsgi", rpm: "mod24_wsgi~3.5~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod24_wsgi-debuginfo", rpm: "mod24_wsgi-debuginfo~3.5~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod24_wsgi-py27", rpm: "mod24_wsgi-py27~3.5~1.17.amzn1", rls: "AMAZON" ) )){
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

