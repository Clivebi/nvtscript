if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1246" );
	script_cve_id( "CVE-2018-15853", "CVE-2018-15857", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864" );
	script_tag( name: "creation_date", value: "2020-03-13 07:17:57 +0000 (Fri, 13 Mar 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for libxkbcommon (EulerOS-SA-2020-1246)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1246" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1246" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libxkbcommon' package(s) announced via the EulerOS-SA-2020-1246 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Endless recursion exists in xkbcomp/expr.c in xkbcommon and libxkbcommon before 0.8.1, which could be used by local attackers to crash xkbcommon users by supplying a crafted keymap file that triggers boolean negation.(CVE-2018-15853)

Unchecked NULL pointer usage when parsing invalid atoms in ExprResolveLhs in xkbcomp/expr.c in xkbcommon before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap file, because lookup failures are mishandled.(CVE-2018-15859)

Unchecked NULL pointer usage in ExprResolveLhs in xkbcomp/expr.c in xkbcommon before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap file that triggers an xkb_intern_atom failure.(CVE-2018-15861)

Unchecked NULL pointer usage in LookupModMask in xkbcomp/expr.c in xkbcommon before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap file with invalid virtual modifiers.(CVE-2018-15862)

Unchecked NULL pointer usage in ResolveStateAndPredicate in xkbcomp/compat.c in xkbcommon before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap file with a no-op modmask expression.(CVE-2018-15863)

Unchecked NULL pointer usage in resolve_keysym in xkbcomp/parser.y in xkbcommon before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap file, because a map access attempt can occur for a map that was never created.(CVE-2018-15864)

An invalid free in ExprAppendMultiKeysymList in xkbcomp/ast-build.c in xkbcommon before 0.8.1 could be used by local attackers to crash xkbcommon keymap parsers or possibly have unspecified other impact by supplying a crafted keymap file.(CVE-2018-15857)" );
	script_tag( name: "affected", value: "'libxkbcommon' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
if(release == "EULEROSVIRTARM64-3.0.2.0"){
	if(!isnull( res = isrpmvuln( pkg: "libxkbcommon", rpm: "libxkbcommon~0.7.1~1.h1", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

