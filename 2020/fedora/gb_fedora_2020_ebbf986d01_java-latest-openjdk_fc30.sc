if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877403" );
	script_version( "2020-02-04T12:23:30+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-04 12:23:30 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:03:47 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Fedora: Security Advisory for java-latest-openjdk (FEDORA-2020-ebbf986d01)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-ebbf986d01" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HRTDPSPIMS5PJTXKFXYTTK6HDKN3TIJP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-latest-openjdk'
  package(s) announced via the FEDORA-2020-ebbf986d01 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK runtime environment." );
	script_tag( name: "affected", value: "'java-latest-openjdk' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "java-latest-openjdk", rpm: "java-latest-openjdk~13.0.2.8~1.rolling.fc30", rls: "FC30" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

