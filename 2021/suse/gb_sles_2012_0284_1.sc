if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0284.1" );
	script_cve_id( "CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-10 02:29:00 +0000 (Wed, 10 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0284-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0284-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120284-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Apache2' package(s) announced via the SUSE-SU-2012:0284-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of apache2 and libapr1 fixes regressions and several security problems.

 * CVE-2012-0031: Fixed a scoreboard corruption (shared mem segment) by child causes crash of privileged parent
(invalid free()) during shutdown.
 * CVE-2012-0053: Fixed an issue in error responses that could expose 'httpOnly' cookies when no custom ErrorDocument is specified for status code 400'.
 * CVE-2007-6750: The 'mod_reqtimeout' module was backported from Apache 2.2.21 to help mitigate the
'Slowloris' Denial of Service attack.

You need to enable the 'mod_reqtimeout' module in your existing apache configuration to make it effective, e.g.
in the APACHE_MODULES line in /etc/sysconfig/apache2. For more detailed information, check also the README file.

Also the following bugs have been fixed:

 * Fixed init script action 'check-reload' to avoid potential crashes. bnc#728876
 * An overlapping memcpy() was replaced by memmove() to make this work with newer glibcs. bnc#738067 bnc#741874
 * libapr1: reset errno to zero to not return previous value despite good status of new operation. bnc#739783

Security Issue references:

 * CVE-2007-6750
>
 * CVE-2012-0031
>
 * CVE-2012-0053
>" );
	script_tag( name: "affected", value: "'Apache2' package(s) on SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.12~1.30.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libapr1", rpm: "libapr1~1.3.3~11.18.19.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libapr1-32bit", rpm: "libapr1-32bit~1.3.3~11.18.19.1", rls: "SLES11.0SP1" ) )){
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

