if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873250" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-12 07:50:49 +0200 (Sat, 12 Aug 2017)" );
	script_cve_id( "CVE-2017-10791", "CVE-2017-10792" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-02 01:29:00 +0000 (Sat, 02 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for pspp FEDORA-2017-03893a3b58" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pspp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "pspp on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-03893a3b58" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y7LSKIXGSMONLQKTTAGZXD2OQOCPE7L3" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "pspp", rpm: "pspp~0.10.2~5.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

