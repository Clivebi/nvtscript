if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879610" );
	script_version( "2021-05-25T12:16:58+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-25 12:16:58 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-20 04:53:36 +0000 (Thu, 20 May 2021)" );
	script_name( "Fedora: Security Advisory for thunderbird (FEDORA-2021-38e1f87ac3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-38e1f87ac3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YCY4TUGDOBCWDS2C7P75DOLQ4OV2CYAV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the FEDORA-2021-38e1f87ac3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~78.10.1~1.fc32", rls: "FC32" ) )){
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

