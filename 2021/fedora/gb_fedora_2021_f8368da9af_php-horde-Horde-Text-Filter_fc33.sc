if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878969" );
	script_version( "2021-03-01T04:08:26+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-01 04:08:26 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 04:03:11 +0000 (Thu, 25 Feb 2021)" );
	script_name( "Fedora: Security Advisory for php-horde-Horde-Text-Filter (FEDORA-2021-f8368da9af)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-f8368da9af" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7WM6BJ72MHPJYXD4BUXE5PS3JZRHR4XA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-Horde-Text-Filter'
  package(s) announced via the FEDORA-2021-f8368da9af advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Common methods for filtering and converting text." );
	script_tag( name: "affected", value: "'php-horde-Horde-Text-Filter' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "php-horde-Horde-Text-Filter", rpm: "php-horde-Horde-Text-Filter~2.3.7~1.fc33", rls: "FC33" ) )){
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

