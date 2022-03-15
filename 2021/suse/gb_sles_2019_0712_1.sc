if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0712.1" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:29 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:01:55 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0712-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0712-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190712-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2019:0712-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ucode-intel fixes the following issues:

Updated to the 20190312 bundle release (bsc#1129231)

New Platforms:
AML-Y22 H0 6-8e-9/10 0000009e Core Gen8 Mobile

WHL-U W0 6-8e-b/d0 000000a4 Core Gen8 Mobile

WHL-U V0 6-8e-d/94 000000b2 Core Gen8 Mobile

CFL-S P0 6-9e-c/22 000000a2 Core Gen9 Desktop

CFL-H R0 6-9e-d/22 000000b0 Core Gen9 Mobile

Updated Platforms:
HSX-E/EP Cx/M1 6-3f-2/6f 0000003d->00000041 Core Gen4 X series,
 Xeon E5 v3

HSX-EX E0 6-3f-4/80 00000012->00000013 Xeon E7 v3

SKX-SP H0/M0/U0 6-55-4/b7 0200004d->0000005a Xeon Scalable

SKX-D M1 6-55-4/b7 0200004d->0000005a Xeon D-21xx

BDX-DE V1 6-56-2/10 00000017->00000019 Xeon D-1520/40

BDX-DE V2/3 6-56-3/10 07000013->07000016 Xeon
 D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19

BDX-DE Y0 6-56-4/10 0f000012->0f000014 Xeon
 D-1557/59/67/71/77/81/87

BDX-NS A0 6-56-5/10 0e00000a->0e00000c Xeon
 D-1513N/23/33/43/53

APL D0 6-5c-9/03 00000032->00000036 Pentium N/J4xxx,
 Celeron N/J3xxx, Atom x5/7-E39xx

APL E0 6-5c-a/03 0000000c->00000010 Atom x5/7-E39xx

GLK B0 6-7a-1/01 00000028->0000002c Pentium Silver
 N/J5xxx, Celeron N/J4xxx

KBL-U/Y H0 6-8e-9/c0 0000008e->0000009a Core Gen7 Mobile

CFL-U43e D0 6-8e-a/c0 00000096->0000009e Core Gen8 Mobile

KBL-H/S/E3 B0 6-9e-9/2a 0000008e->0000009a Core Gen7, Xeon E3 v6

CFL-H/S/E3 U0 6-9e-a/22 00000096->000000aa Core Gen8 Desktop,
 Mobile, Xeon E

CFL-S B0 6-9e-b/02 0000008e->000000aa Core Gen8" );
	script_tag( name: "affected", value: "'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "ucode-intel", rpm: "ucode-intel~20190312~3.12.1", rls: "SLES15.0" ) )){
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

