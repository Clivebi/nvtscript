if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874645" );
	script_version( "2021-06-11T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 02:00:27 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-05 13:07:02 +0200 (Tue, 05 Jun 2018)" );
	script_cve_id( "CVE-2016-9396", "CVE-2016-9387", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2016-9560" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-29 01:29:00 +0000 (Fri, 29 Jun 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for jasper FEDORA-2018-ec39fe2c9c" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "jasper on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-ec39fe2c9c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z4Y3IHK6BEQT5WT5T4M6MVARCCSWXQLU" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "jasper", rpm: "jasper~2.0.14~5.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
