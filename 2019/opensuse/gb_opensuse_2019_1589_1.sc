if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852571" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-16838" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-20 02:00:50 +0000 (Thu, 20 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for sssd (openSUSE-SU-2019:1589-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1589-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00051.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sssd'
  package(s) announced via the openSUSE-SU-2019:1589-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sssd fixes the following issues:

  Security issue fixed:

  - CVE-2018-16838: Fixed an authentication bypass related to the Group
  Policy Objects implementation (bsc#1124194).

  Non-security issues fixed:

  - Allow defaults sudoRole without sudoUser attribute (bsc#1135247)

  - Missing GPOs directory could have led to login problems (bsc#1132879)

  - Fix a crash by adding a netgroup counter to struct nss_enum_index
  (bsc#1132657)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1589=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1589=1" );
	script_tag( name: "affected", value: "'sssd' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac-devel", rpm: "libipa_hbac-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0", rpm: "libipa_hbac0~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0-debuginfo", rpm: "libipa_hbac0-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnfsidmap-sss", rpm: "libnfsidmap-sss~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnfsidmap-sss-debuginfo", rpm: "libnfsidmap-sss-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap-devel", rpm: "libsss_certmap-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap0", rpm: "libsss_certmap0~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_certmap0-debuginfo", rpm: "libsss_certmap0-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap-devel", rpm: "libsss_idmap-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0", rpm: "libsss_idmap0~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0-debuginfo", rpm: "libsss_idmap0-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap-devel", rpm: "libsss_nss_idmap-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap0", rpm: "libsss_nss_idmap0~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap0-debuginfo", rpm: "libsss_nss_idmap0-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp-devel", rpm: "libsss_simpleifp-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp0", rpm: "libsss_simpleifp0~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_simpleifp0-debuginfo", rpm: "libsss_simpleifp0-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ipa_hbac", rpm: "python3-ipa_hbac~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ipa_hbac-debuginfo", rpm: "python3-ipa_hbac-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss-murmur", rpm: "python3-sss-murmur~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss-murmur-debuginfo", rpm: "python3-sss-murmur-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss_nss_idmap", rpm: "python3-sss_nss_idmap~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sss_nss_idmap-debuginfo", rpm: "python3-sss_nss_idmap-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sssd-config", rpm: "python3-sssd-config~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-sssd-config-debuginfo", rpm: "python3-sssd-config-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd", rpm: "sssd~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad", rpm: "sssd-ad~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad-debuginfo", rpm: "sssd-ad-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-dbus", rpm: "sssd-dbus~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-dbus-debuginfo", rpm: "sssd-dbus-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debuginfo", rpm: "sssd-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debugsource", rpm: "sssd-debugsource~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa", rpm: "sssd-ipa~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa-debuginfo", rpm: "sssd-ipa-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5", rpm: "sssd-krb5~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common", rpm: "sssd-krb5-common~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common-debuginfo", rpm: "sssd-krb5-common-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-debuginfo", rpm: "sssd-krb5-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap", rpm: "sssd-ldap~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap-debuginfo", rpm: "sssd-ldap-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy", rpm: "sssd-proxy~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy-debuginfo", rpm: "sssd-proxy-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools", rpm: "sssd-tools~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools-debuginfo", rpm: "sssd-tools-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient", rpm: "sssd-wbclient~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient-debuginfo", rpm: "sssd-wbclient-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-wbclient-devel", rpm: "sssd-wbclient-devel~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-winbind-idmap", rpm: "sssd-winbind-idmap~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-winbind-idmap-debuginfo", rpm: "sssd-winbind-idmap-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-32bit", rpm: "sssd-32bit~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-32bit-debuginfo", rpm: "sssd-32bit-debuginfo~1.16.1~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
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
