if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874109" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 07:58:58 +0100 (Thu, 08 Feb 2018)" );
	script_cve_id( "CVE-2017-17485", "CVE-2018-5968", "CVE-2017-15095", "CVE-2017-7525" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-19 15:51:00 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for jackson-databind FEDORA-2018-e4b025841e" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "jackson-databind on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-e4b025841e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WW7SXEPYMKLVPDYOEHSN52CK3P6WMIQG" );
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
	if(( res = isrpmvuln( pkg: "jackson-databind", rpm: "jackson-databind~2.7.6~8.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

