if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878353" );
	script_version( "2020-09-28T10:54:24+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-28 10:54:24 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-26 03:13:23 +0000 (Sat, 26 Sep 2020)" );
	script_name( "Fedora: Security Advisory for swtpm (FEDORA-2020-561c908a9a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-561c908a9a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CQRGVLGYTVNR3NHWJL7OCRTLATI3NKA7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'swtpm'
  package(s) announced via the FEDORA-2020-561c908a9a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "TPM emulator built on libtpms providing TPM functionality for QEMU VMs" );
	script_tag( name: "affected", value: "'swtpm' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "swtpm", rpm: "swtpm~0.3.4~2.20200811git80f0418.fc33", rls: "FC33" ) )){
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

