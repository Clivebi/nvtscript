if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852745" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-19052" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-21 00:15:00 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-21 02:01:00 +0000 (Mon, 21 Oct 2019)" );
	script_name( "openSUSE: Security Advisory for lighttpd (openSUSE-SU-2019:2347-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2347-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00054.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lighttpd'
  package(s) announced via the openSUSE-SU-2019:2347-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for lighttpd to version 1.4.54 fixes the following issues:

  Security issues fixed:

  - CVE-2018-19052: Fixed a path traversal in mod_alias (boo#1115016).

  - Changed the default TLS configuration of lighttpd for better security
  out-of-the-box (boo#1087369).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2347=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2347=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2019-2347=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-2347=1" );
	script_tag( name: "affected", value: "'lighttpd' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "lighttpd", rpm: "lighttpd~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debuginfo", rpm: "lighttpd-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debugsource", rpm: "lighttpd-debugsource~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_gssapi", rpm: "lighttpd-mod_authn_gssapi~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_gssapi-debuginfo", rpm: "lighttpd-mod_authn_gssapi-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_ldap", rpm: "lighttpd-mod_authn_ldap~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_ldap-debuginfo", rpm: "lighttpd-mod_authn_ldap-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_mysql", rpm: "lighttpd-mod_authn_mysql~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_mysql-debuginfo", rpm: "lighttpd-mod_authn_mysql-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_pam", rpm: "lighttpd-mod_authn_pam~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_pam-debuginfo", rpm: "lighttpd-mod_authn_pam-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_sasl", rpm: "lighttpd-mod_authn_sasl~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_authn_sasl-debuginfo", rpm: "lighttpd-mod_authn_sasl-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml", rpm: "lighttpd-mod_cml~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml-debuginfo", rpm: "lighttpd-mod_cml-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip", rpm: "lighttpd-mod_geoip~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip-debuginfo", rpm: "lighttpd-mod_geoip-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet", rpm: "lighttpd-mod_magnet~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet-debuginfo", rpm: "lighttpd-mod_magnet-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_maxminddb", rpm: "lighttpd-mod_maxminddb~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_maxminddb-debuginfo", rpm: "lighttpd-mod_maxminddb-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost", rpm: "lighttpd-mod_mysql_vhost~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost-debuginfo", rpm: "lighttpd-mod_mysql_vhost-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool", rpm: "lighttpd-mod_rrdtool~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool-debuginfo", rpm: "lighttpd-mod_rrdtool-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl", rpm: "lighttpd-mod_trigger_b4_dl~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl-debuginfo", rpm: "lighttpd-mod_trigger_b4_dl-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_dbi", rpm: "lighttpd-mod_vhostdb_dbi~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_dbi-debuginfo", rpm: "lighttpd-mod_vhostdb_dbi-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_ldap", rpm: "lighttpd-mod_vhostdb_ldap~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_ldap-debuginfo", rpm: "lighttpd-mod_vhostdb_ldap-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_mysql", rpm: "lighttpd-mod_vhostdb_mysql~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_mysql-debuginfo", rpm: "lighttpd-mod_vhostdb_mysql-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_pgsql", rpm: "lighttpd-mod_vhostdb_pgsql~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_vhostdb_pgsql-debuginfo", rpm: "lighttpd-mod_vhostdb_pgsql-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav", rpm: "lighttpd-mod_webdav~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav-debuginfo", rpm: "lighttpd-mod_webdav-debuginfo~1.4.54~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

