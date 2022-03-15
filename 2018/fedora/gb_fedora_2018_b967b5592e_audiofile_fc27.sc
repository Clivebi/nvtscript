if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875205" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-18 06:45:39 +0200 (Thu, 18 Oct 2018)" );
	script_cve_id( "CVE-2018-13440", "CVE-2018-17095" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-09 15:08:00 +0000 (Tue, 09 Feb 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for audiofile FEDORA-2018-b967b5592e" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'audiofile'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "affected", value: "audiofile on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-b967b5592e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PQ73U2FYF2HL6IYM7Q5WOINGFUSOK7MK" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "audiofile", rpm: "audiofile~0.3.6~21.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

