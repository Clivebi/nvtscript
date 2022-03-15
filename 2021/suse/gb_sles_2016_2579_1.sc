if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2579.1" );
	script_cve_id( "CVE-2014-0249" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2579-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2579-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162579-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sssd' package(s) announced via the SUSE-SU-2016:2579-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sssd fixes one security issue and three bugs.
The following vulnerability was fixed:
- CVE-2014-0249: Incorrect expansion of group membership when encountering
 a non-POSIX group. (bsc#880245)
The following non-security fixes were also included:
- Prevent crashes of statically linked binaries using getpwuid when sssd
 is used and nscd is turned off or has caching disabled. (bsc#993582)
- Add logrotate configuration to prevent log files from growing too large
 when running with debug mode enabled. (bsc#1004220)
- Order sudo rules by the same logic used by the native LDAP support from
 sudo. (bsc#1002973)" );
	script_tag( name: "affected", value: "'sssd' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0", rpm: "libipa_hbac0~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac0-debuginfo", rpm: "libipa_hbac0-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0", rpm: "libsss_idmap0~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap0-debuginfo", rpm: "libsss_idmap0-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_sudo", rpm: "libsss_sudo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_sudo-debuginfo", rpm: "libsss_sudo-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-sssd-config", rpm: "python-sssd-config~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-sssd-config-debuginfo", rpm: "python-sssd-config-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd", rpm: "sssd~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-32bit", rpm: "sssd-32bit~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad", rpm: "sssd-ad~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad-debuginfo", rpm: "sssd-ad-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debuginfo", rpm: "sssd-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debuginfo-32bit", rpm: "sssd-debuginfo-32bit~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-debugsource", rpm: "sssd-debugsource~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa", rpm: "sssd-ipa~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa-debuginfo", rpm: "sssd-ipa-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5", rpm: "sssd-krb5~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common", rpm: "sssd-krb5-common~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common-debuginfo", rpm: "sssd-krb5-common-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-debuginfo", rpm: "sssd-krb5-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap", rpm: "sssd-ldap~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap-debuginfo", rpm: "sssd-ldap-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy", rpm: "sssd-proxy~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy-debuginfo", rpm: "sssd-proxy-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools", rpm: "sssd-tools~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-tools-debuginfo", rpm: "sssd-tools-debuginfo~1.11.5.1~28.1", rls: "SLES12.0SP1" ) )){
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

