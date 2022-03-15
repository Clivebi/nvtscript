if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874330" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-06 10:09:12 +0200 (Fri, 06 Apr 2018)" );
	script_cve_id( "CVE-2018-7728", "CVE-2018-7729", "CVE-2018-7730", "CVE-2018-7731", "CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18234", "CVE-2017-18235", "CVE-2017-18237" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for exempi FEDORA-2018-c442aad4dc" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exempi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "exempi on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-c442aad4dc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H4PKNNGR3XYNB7B7BYNWTABCOPERDDLB" );
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
	if(( res = isrpmvuln( pkg: "exempi", rpm: "exempi~2.4.5~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

