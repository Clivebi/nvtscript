if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879797" );
	script_version( "2021-07-06T12:11:22+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 03:18:41 +0000 (Tue, 06 Jul 2021)" );
	script_name( "Fedora: Security Advisory for libtpms (FEDORA-2021-57e3c4261a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-57e3c4261a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DZI42OR3JUEGWRKEVCOHL2FPTJVYCYBT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtpms'
  package(s) announced via the FEDORA-2021-57e3c4261a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A library providing TPM functionality for VMs. Targeted for integration
into Qemu." );
	script_tag( name: "affected", value: "'libtpms' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtpms", rpm: "libtpms~0.8.4~1.20210624gita594c4692a.fc33", rls: "FC33" ) )){
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

