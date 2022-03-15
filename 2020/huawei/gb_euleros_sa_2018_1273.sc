if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1273" );
	script_cve_id( "CVE-2017-12173" );
	script_tag( name: "creation_date", value: "2020-01-23 11:19:44 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for sssd (EulerOS-SA-2018-1273)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1273" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1273" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'sssd' package(s) announced via the EulerOS-SA-2018-1273 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that sssd's sysdb_search_user_by_upn_res() function did not sanitize requests when querying its local cache and was vulnerable to injection. In a centralized login environment, if a password hash was locally cached for a given user, an authenticated attacker could use this flaw to retrieve it.(CVE-2017-12173)" );
	script_tag( name: "affected", value: "'sssd' package(s) on Huawei EulerOS Virtualization 2.5.1." );
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
if(release == "EULEROSVIRT-2.5.1"){
	if(!isnull( res = isrpmvuln( pkg: "libipa_hbac", rpm: "libipa_hbac~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_idmap", rpm: "libsss_idmap~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsss_nss_idmap", rpm: "libsss_nss_idmap~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-sssdconfig", rpm: "python-sssdconfig~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd", rpm: "sssd~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ad", rpm: "sssd-ad~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-client", rpm: "sssd-client~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-common", rpm: "sssd-common~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-common-pac", rpm: "sssd-common-pac~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ipa", rpm: "sssd-ipa~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5", rpm: "sssd-krb5~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-krb5-common", rpm: "sssd-krb5-common~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-ldap", rpm: "sssd-ldap~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sssd-proxy", rpm: "sssd-proxy~1.13.0~40.2.h1", rls: "EULEROSVIRT-2.5.1" ) )){
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

