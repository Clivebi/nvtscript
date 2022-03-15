if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876275" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-3276", "CVE-2018-3200", "CVE-2018-3137", "CVE-2018-3284", "CVE-2018-3195", "CVE-2018-3173", "CVE-2018-3212", "CVE-2018-3279", "CVE-2018-3162", "CVE-2018-3247", "CVE-2018-3156", "CVE-2018-3161", "CVE-2018-3278", "CVE-2018-3174", "CVE-2018-3282", "CVE-2018-3285", "CVE-2018-3187", "CVE-2018-3277", "CVE-2018-3144", "CVE-2018-3145", "CVE-2018-3170", "CVE-2018-3186", "CVE-2018-3182", "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3283", "CVE-2018-3171", "CVE-2018-3251", "CVE-2018-3286", "CVE-2018-3185", "CVE-2018-3280", "CVE-2018-3203", "CVE-2018-3155" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:41:47 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for community-mysql FEDORA-2018-c82fc3e109" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-c82fc3e109" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U4YB2A4YOG3UDLU26ITP52N353DASGYE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2018-c82fc3e109 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files." );
	script_tag( name: "affected", value: "'community-mysql' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "community-mysql", rpm: "community-mysql~8.0.13~1.fc29", rls: "FC29" ) )){
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

