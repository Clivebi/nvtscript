if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854137" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_cve_id( "CVE-2021-3621" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-04 01:02:49 +0000 (Sat, 04 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for sssd (openSUSE-SU-2021:2941-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2941-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/32JUFL2YE6SH6B4KF762VVSDUIQI7ZKU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sssd'
  package(s) announced via the openSUSE-SU-2021:2941-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sssd fixes the following issues:

  - CVE-2021-3621: Fixed shell command injection in sssctl via the
       logs-fetch and cache-expire subcommands (bsc#1189492).

  - Add LDAPS support for the AD provider (bsc#1183735).

  - Improve logs to record the reason why internal watchdog terminates a
       process (bsc#1187120).

  - Fix watchdog not terminating tasks (bsc#1187120)." );
	script_tag( name: "affected", value: "'sssd' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac-devel", rpm: "libipa_hbac-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0", rpm: "libipa_hbac0~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0-debuginfo", rpm: "libipa_hbac0-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnfsidmap-sss", rpm: "libnfsidmap-sss~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnfsidmap-sss-debuginfo", rpm: "libnfsidmap-sss-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap-devel", rpm: "libsss_certmap-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap0", rpm: "libsss_certmap0~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap0-debuginfo", rpm: "libsss_certmap0-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap-devel", rpm: "libsss_idmap-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0", rpm: "libsss_idmap0~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0-debuginfo", rpm: "libsss_idmap0-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap-devel", rpm: "libsss_nss_idmap-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap0", rpm: "libsss_nss_idmap0~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap0-debuginfo", rpm: "libsss_nss_idmap0-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp-devel", rpm: "libsss_simpleifp-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp0", rpm: "libsss_simpleifp0~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp0-debuginfo", rpm: "libsss_simpleifp0-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ipa_hbac", rpm: "python3-ipa_hbac~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ipa_hbac-debuginfo", rpm: "python3-ipa_hbac-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss-murmur", rpm: "python3-sss-murmur~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss-murmur-debuginfo", rpm: "python3-sss-murmur-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss_nss_idmap", rpm: "python3-sss_nss_idmap~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss_nss_idmap-debuginfo", rpm: "python3-sss_nss_idmap-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sssd-config", rpm: "python3-sssd-config~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sssd-config-debuginfo", rpm: "python3-sssd-config-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd", rpm: "sssd~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad", rpm: "sssd-ad~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad-debuginfo", rpm: "sssd-ad-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-common", rpm: "sssd-common~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-common-debuginfo", rpm: "sssd-common-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-dbus", rpm: "sssd-dbus~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-dbus-debuginfo", rpm: "sssd-dbus-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debugsource", rpm: "sssd-debugsource~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa", rpm: "sssd-ipa~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa-debuginfo", rpm: "sssd-ipa-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5", rpm: "sssd-krb5~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common", rpm: "sssd-krb5-common~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common-debuginfo", rpm: "sssd-krb5-common-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-debuginfo", rpm: "sssd-krb5-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap", rpm: "sssd-ldap~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap-debuginfo", rpm: "sssd-ldap-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy", rpm: "sssd-proxy~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy-debuginfo", rpm: "sssd-proxy-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools", rpm: "sssd-tools~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools-debuginfo", rpm: "sssd-tools-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient", rpm: "sssd-wbclient~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient-debuginfo", rpm: "sssd-wbclient-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient-devel", rpm: "sssd-wbclient-devel~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-winbind-idmap", rpm: "sssd-winbind-idmap~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-winbind-idmap-debuginfo", rpm: "sssd-winbind-idmap-debuginfo~1.16.1~23.11.1", rls: "openSUSELeap15.3" ) )){
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

