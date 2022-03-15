if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1081.1" );
	script_cve_id( "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0226", "CVE-2014-0231" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1081-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1081-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141081-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2014:1081-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This apache2 update fixes the following security and non-security issues:

 * mod_cgid denial of service (CVE-2014-0231, bnc#887768)
 * mod_status heap-based buffer overflow (CVE-2014-0226, bnc#887765)
 * mod_dav denial of service (CVE-2013-6438, bnc#869105)
 * log_cookie mod_log_config.c remote denial of service (CVE-2014-0098,
 bnc#869106)
 * Support ECDH in Apache2 (bnc#859916)
 * apache fails to start with SSL on Xen kernel at boot time
 (bnc#852401)

Security Issues:

 * CVE-2014-0098
 * CVE-2013-6438
 * CVE-2014-0226
 * CVE-2014-0231" );
	script_tag( name: "affected", value: "'apache2' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.12~1.48.1", rls: "SLES11.0SP1" ) )){
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

