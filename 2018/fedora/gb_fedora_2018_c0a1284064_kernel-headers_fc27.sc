if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875132" );
	script_version( "2021-06-07T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 11:00:20 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-02 08:50:35 +0200 (Tue, 02 Oct 2018)" );
	script_cve_id( "CVE-2018-14633" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-28 18:27:00 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for kernel-headers FEDORA-2018-c0a1284064" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-headers'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "affected", value: "kernel-headers on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-c0a1284064" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I7OBU5DPKJDOFFMTWBPP5VL5H4BAAZ6J" );
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
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~4.18.10~100.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

