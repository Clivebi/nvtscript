if(description){
	script_tag( name: "affected", value: "libkcddb on Fedora 17" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_oid( "1.3.6.1.4.1.25623.1.0.865980" );
	script_version( "2021-07-02T11:00:44+0000" );
	script_tag( name: "last_modification", value: "2021-07-02 11:00:44 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-06-18 10:38:10 +0530 (Tue, 18 Jun 2013)" );
	script_cve_id( "CVE-2013-2120" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-21 16:15:00 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Fedora Update for libkcddb FEDORA-2013-10182" );
	script_xref( name: "FEDORA", value: "2013-10182" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109181.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libkcddb'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC17"){
	if(( res = isrpmvuln( pkg: "libkcddb", rpm: "libkcddb~4.10.4~1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
