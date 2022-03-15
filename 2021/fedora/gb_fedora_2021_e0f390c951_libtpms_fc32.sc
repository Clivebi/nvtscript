if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879053" );
	script_version( "2021-03-17T09:33:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-17 09:33:35 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 10:40:10 +0000 (Wed, 10 Mar 2021)" );
	script_name( "Fedora: Security Advisory for libtpms (FEDORA-2021-e0f390c951)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-e0f390c951" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VSBHZZFQOKBAPAAVQSRDOS7UOFX2NLXP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtpms'
  package(s) announced via the FEDORA-2021-e0f390c951 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A library providing TPM functionality for VMs. Targeted for integration
into Qemu." );
	script_tag( name: "affected", value: "'libtpms' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtpms", rpm: "libtpms~0.7.7~0.20210302gitfd5bd3fb1d.fc32", rls: "FC32" ) )){
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

