if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808009" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-09 05:17:58 +0200 (Mon, 09 May 2016)" );
	script_cve_id( "CVE-2016-1926" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for openvas-libraries FEDORA-2016-9851" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvas-libraries'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "openvas-libraries on Fedora 22" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-9851" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184475.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC22" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC22"){
	if(( res = isrpmvuln( pkg: "openvas-libraries", rpm: "openvas-libraries~8.0.7~2.fc22", rls: "FC22" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

