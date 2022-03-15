if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875217" );
	script_version( "2021-06-08T02:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 02:00:22 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-23 12:15:51 +0200 (Tue, 23 Oct 2018)" );
	script_cve_id( "CVE-2018-12543", "CVE-2017-7651", "CVE-2017-7652" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for mosquitto FEDORA-2018-a115b0b80e" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mosquitto'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "affected", value: "mosquitto on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-a115b0b80e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/77EDTTTRVLQNEVCGONNDBXVZ6KXYAGMA" );
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
	if(( res = isrpmvuln( pkg: "mosquitto", rpm: "mosquitto~1.5.3~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

