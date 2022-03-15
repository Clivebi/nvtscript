if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874741" );
	script_version( "2021-06-11T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-26 06:06:51 +0200 (Tue, 26 Jun 2018)" );
	script_cve_id( "CVE-2017-7380", "CVE-2017-7381", "CVE-2017-7382", "CVE-2017-7383", "CVE-2017-5852", "CVE-2017-5853", "CVE-2017-6844", "CVE-2017-5854", "CVE-2017-5855", "CVE-2017-5886", "CVE-2018-8000", "CVE-2017-6840", "CVE-2017-6842", "CVE-2017-6843", "CVE-2017-6845", "CVE-2017-6847", "CVE-2017-6848", "CVE-2017-7378", "CVE-2017-7379", "CVE-2017-7994", "CVE-2017-8054", "CVE-2017-8378", "CVE-2017-8787", "CVE-2018-5295", "CVE-2018-5308", "CVE-2015-8981", "CVE-2017-8053", "CVE-2018-5296" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for podofo FEDORA-2018-2f3c0cdf93" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'podofo'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
the target host." );
	script_tag( name: "affected", value: "podofo on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-2f3c0cdf93" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OEMA3VKO24P6OVWPTL7HRIU53H6FCBAJ" );
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
	if(( res = isrpmvuln( pkg: "podofo", rpm: "podofo~0.9.5~9.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

