if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874148" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 08:19:36 +0100 (Tue, 27 Feb 2018)" );
	script_cve_id( "CVE-2018-7050", "CVE-2018-7051", "CVE-2018-7052", "CVE-2018-7053", "CVE-2018-7054" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 17:37:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for irssi FEDORA-2018-cbc52e8812" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "irssi on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-cbc52e8812" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZQK7QPMCHH2NGXGVLKDB44MEQCP6QR3P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "irssi", rpm: "irssi~1.0.7~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

