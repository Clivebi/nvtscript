if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874262" );
	script_version( "2021-06-10T11:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-21 15:11:56 +0100 (Wed, 21 Mar 2018)" );
	script_cve_id( "CVE-2017-8782", "CVE-2017-9988", "CVE-2017-9989", "CVE-2017-11704", "CVE-2017-11728", "CVE-2017-11729", "CVE-2017-11730", "CVE-2017-11731", "CVE-2017-11732", "CVE-2017-11733", "CVE-2017-11734", "CVE-2017-16883", "CVE-2017-16898", "CVE-2018-5251", "CVE-2018-5294", "CVE-2018-6315", "CVE-2018-6359" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 12:41:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for ming FEDORA-2018-38a0e1e6f5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ming'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ming on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-38a0e1e6f5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z65NZJOBGTBW6Y3JD3IX5GIEKCRY7DQD" );
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
	if(( res = isrpmvuln( pkg: "ming", rpm: "ming~0.4.8~5.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

