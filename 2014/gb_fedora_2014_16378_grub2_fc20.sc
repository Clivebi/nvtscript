if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868573" );
	script_version( "2020-02-18T15:18:54+0000" );
	script_tag( name: "last_modification", value: "2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-12-12 06:02:59 +0100 (Fri, 12 Dec 2014)" );
	script_cve_id( "CVE-2014-4607" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for grub2 FEDORA-2014-16378" );
	script_tag( name: "summary", value: "Check the version of grub2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "grub2 on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2014-16378" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145948.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.00~27.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

