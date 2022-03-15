if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874365" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-18 08:54:26 +0200 (Wed, 18 Apr 2018)" );
	script_cve_id( "CVE-2018-10021", "CVE-2017-18232", "CVE-2018-7995", "CVE-2018-8043", "CVE-2018-7757", "CVE-2018-5803", "CVE-2018-1065", "CVE-2018-1000026", "CVE-2018-5750", "CVE-2018-1000004", "CVE-2018-5344", "CVE-2018-5332", "CVE-2018-5333", "CVE-2017-17862", "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-17852", "CVE-2017-17853", "CVE-2017-17854", "CVE-2017-17855", "CVE-2017-17856", "CVE-2017-17857", "CVE-2017-17741", "CVE-2017-17712", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17448", "CVE-2017-17558", "CVE-2017-8824", "CVE-2017-1000405", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16644", "CVE-2017-16647", "CVE-2017-15115", "CVE-2017-16532", "CVE-2017-16538", "CVE-2017-12193", "CVE-2017-12190", "CVE-2017-5123", "CVE-2017-15265", "CVE-2017-1000255", "CVE-2017-14954", "CVE-2017-14497", "CVE-2017-12154", "CVE-2017-12153", "CVE-2017-1000251", "CVE-2017-14051", "CVE-2017-13693", "CVE-2017-13694", "CVE-2017-13695", "CVE-2017-7558", "CVE-2017-12134", "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-7533", "CVE-2017-10810" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for kernel FEDORA-2018-4ca01704a2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "kernel on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-4ca01704a2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3MAKT7ZDC6T4B52QFNRBYKWU75JMUX5C" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.15.17~200.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
