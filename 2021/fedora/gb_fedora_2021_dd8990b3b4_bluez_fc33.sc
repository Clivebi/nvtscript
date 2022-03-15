if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879925" );
	script_version( "2021-09-20T15:19:16+0000" );
	script_cve_id( "CVE-2021-3658" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 15:19:16 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 03:13:11 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Fedora: Security Advisory for bluez (FEDORA-2021-dd8990b3b4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-dd8990b3b4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DMBDS2YZYA57ZZ536MUH34JT2M2UVGBO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bluez'
  package(s) announced via the FEDORA-2021-dd8990b3b4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Utilities for use in Bluetooth applications:

  - hcitool

  - hciattach

  - hciconfig

  - bluetoothd

  - l2ping

  - rfcomm

  - sdptool

  - bluetoothctl

  - btmon

  - hcidump

  - l2test

  - rctest

  - gatttool

  - start scripts (Red Hat)

  - pcmcia configuration files

  - avinfo

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A." );
	script_tag( name: "affected", value: "'bluez' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "bluez", rpm: "bluez~5.60~1.fc33", rls: "FC33" ) )){
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

