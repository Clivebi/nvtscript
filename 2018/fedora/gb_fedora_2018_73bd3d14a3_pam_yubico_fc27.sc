if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874893" );
	script_version( "2021-06-07T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 11:00:20 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-04 06:07:19 +0200 (Sat, 04 Aug 2018)" );
	script_cve_id( "CVE-2018-9275" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-21 15:33:00 +0000 (Mon, 21 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for pam_yubico FEDORA-2018-73bd3d14a3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam_yubico'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "pam_yubico on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-73bd3d14a3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IZZPVLNDMCZSENY2SD4VLV747BKZIQRX" );
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
	if(( res = isrpmvuln( pkg: "pam_yubico", rpm: "pam_yubico~2.26~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

