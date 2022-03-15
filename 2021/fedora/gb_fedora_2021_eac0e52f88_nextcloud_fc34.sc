if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879816" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2020-8296", "CVE-2021-22878", "CVE-2021-22877", "CVE-2021-22915" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-11 03:22:10 +0000 (Sun, 11 Jul 2021)" );
	script_name( "Fedora: Security Advisory for nextcloud (FEDORA-2021-eac0e52f88)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-eac0e52f88" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L6BO6P6MP2MOWA6PZRXX32PLWPXN5O4S" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nextcloud'
  package(s) announced via the FEDORA-2021-eac0e52f88 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NextCloud gives you universal access to your files through a web interface or
WebDAV. It also provides a platform to easily view & sync your contacts,
calendars and bookmarks across all your devices and enables basic editing right
on the web. NextCloud is extendable via a simple but powerful API for
applications and plugins." );
	script_tag( name: "affected", value: "'nextcloud' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "nextcloud", rpm: "nextcloud~20.0.10~1.fc34", rls: "FC34" ) )){
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

