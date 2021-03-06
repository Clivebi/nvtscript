if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876559" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-07-07 02:13:11 +0000 (Sun, 07 Jul 2019)" );
	script_name( "Fedora Update for filezilla FEDORA-2019-7b9af09b17" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-7b9af09b17" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DYM7BZFULYL5BCP2SHUMLBOW2W6CDWPX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'filezilla'
  package(s) announced via the FEDORA-2019-7b9af09b17 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "FileZilla is a FTP, FTPS and SFTP client for Linux with a lot of features.

  - Supports FTP, FTP over SSL/TLS (FTPS) and SSH File Transfer Protocol (SFTP)

  - Cross-platform

  - Available in many languages

  - Supports resume and transfer of large files >4GB

  - Easy to use Site Manager and transfer queue

  - Drag & drop support

  - Speed limits

  - Filename filters

  - Network configuration wizard" );
	script_tag( name: "affected", value: "'filezilla' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "filezilla", rpm: "filezilla~3.43.0~1.fc30", rls: "FC30" ) )){
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

