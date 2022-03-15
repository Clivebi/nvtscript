if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854160" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-32785", "CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-04 17:27:00 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-14 01:01:55 +0000 (Tue, 14 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for apache2-mod_auth_openidc (openSUSE-SU-2021:3020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:3020-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/54B4RYNP5L63X2FMX2QCVYB2LGLL42IY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2-mod_auth_openidc'
  package(s) announced via the openSUSE-SU-2021:3020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache2-mod_auth_openidc fixes the following issues:

  - CVE-2021-32785: format string bug via hiredis (bsc#1188638)

  - CVE-2021-32786: open redirect in logout functionality (bsc#1188639)

  - CVE-2021-32791: Hardcoded static IV and AAD with a reused key in AES GCM
       encryption (bsc#1188849)

  - CVE-2021-32792: XSS when using OIDCPreservePost On (bsc#1188848)" );
	script_tag( name: "affected", value: "'apache2-mod_auth_openidc' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc", rpm: "apache2-mod_auth_openidc~2.3.8~3.15.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc-debuginfo", rpm: "apache2-mod_auth_openidc-debuginfo~2.3.8~3.15.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc-debugsource", rpm: "apache2-mod_auth_openidc-debugsource~2.3.8~3.15.1", rls: "openSUSELeap15.3" ) )){
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

