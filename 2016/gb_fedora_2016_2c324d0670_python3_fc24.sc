if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809109" );
	script_version( "2019-12-18T09:57:42+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-12 05:58:47 +0200 (Fri, 12 Aug 2016)" );
	script_cve_id( "CVE-2016-1000110" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for python3 FEDORA-2016-2c324d0670" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "python3 on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-2c324d0670" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2YW45Y2P67PX7CI2K6WVFJTQTUIO452O" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "python3", rpm: "python3~3.5.1~13.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

