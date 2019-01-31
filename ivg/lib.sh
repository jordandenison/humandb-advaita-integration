
submit_requests(){

	if [ "${output_file}" = "${inputFilePath}" ]
	then
		output_file_error=${output_file}.error.json
		message="Error: input file is the same as output file"
		logger ${log_opts} "${message}. For details, see ${output_file_error}. Exiting..."
		jq --null-input --arg message "${message}" --arg inputFilePath "${inputFilePath}" --arg outputFilePath "${output_file}" '{errorMessage: $message, inputFilePath: $inputFilePath, outputFilePath: $outputFilePath }'  >> ${output_file_error}
		exit 1
	fi

	if [ -f "${inputFilePath}" ]
	then
		logger ${log_opts} "${inputFilePath} found."
	else
		message="Error: ${inputFilePath} not found"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg inputFilePath "${inputFilePath}" '{errorMessage: $message, inputFilePath: $inputFilePath }'  >> ${output_file}
		exit 1
	fi

	upload_file 0
	logger ${log_opts} "File uploaded successfully: ${fileId}"

	logger ${log_opts} "submitting request to create a new report"
	create_new_report 0

	#logger ${log_opts} "Response from ${host}/${version}/analysisRequests is \n $response \n "
	analysisRequestId=$(jq -r .id ${http_output_file})
	logger ${log_opts} "Analysis-Request-Id is $analysisRequestId"
	status=$(jq -r .status ${http_output_file})
	if [ ${do_not_follow} -eq 1 ] && [ "$status" != "COMPLETED" ] && [ "$status" != "ERROR" ] && [ "$status" != "TIMEOUT" ]; then
		logger ${log_opts} "Analysis request with id '${analysisRequestId}' was created. To check the status, run the command again by providing the analysis request id instead of the input file."
		exit 0
	fi


}

check_status_continously(){

	output_file=${OUTPUT_FILE_PATH:-${inputFilePath}_${analysisRequestId}.json}
	html_output_file=${HTML_FILE_PATH:-${inputFilePath}_${analysisRequestId}.b64html}

	while [ "$status" != "COMPLETED" ] && [ "$status" != "ERROR" ] && [ "$status" != "TIMEOUT" ]
	do
		cat ${http_output_file} > ${output_file}
		logger ${log_opts} "Checking status ...."
		check_status 0
		sleep ${sleep_time}
	done

	mv "${http_output_file}" "${output_file}"
	logger ${log_opts} "Output file written to ${output_file}"

	if [ "${status}" = "COMPLETED" ]; then
		write_output 0
	fi



}

check_status_once(){

	output_file=${OUTPUT_FILE_PATH:-${analysisRequestId}.json}
	html_output_file=${HTML_FILE_PATH:-${analysisRequestId}.b64html}

	cat ${http_output_file} > ${output_file}
	logger ${log_opts} "Checking status ...."
	check_status 0

	if [ "$status" = "COMPLETED" ] || [ "$status" = "ERROR" ] || [ "$status" = "TIMEOUT" ]; then

		mv "${http_output_file}" "${output_file}"
		logger ${log_opts} "Output file written to ${output_file}"

		if [ "${status}" = "COMPLETED" ];then
			write_output 0
		fi
	fi
}


write_output(){

	reportUrl=$(jq -r .output.report._links.ui.href ${output_file})
	title=$(jq -r .parameters.title ${output_file})
	description=$(jq -r .parameters.description ${output_file})

	echo "data:text/html;base64," > ${html_output_file}
	sed "s,{{title}},${title},g" ${html_template} | sed "s,{{description}},${description},g"  | sed "s,{{reportUrl}},${reportUrl},g" | openssl base64 >> ${html_output_file}

	logger ${log_opts} "HTML Output file written to ${html_output_file}"

}

get_access_token(){
	logger ${log_opts} "Getting access token..."
	HTTP_STATUS=$(curl ${curl_opts} -X POST --write-out "%{http_code}" -H "Content-Type: application/json" -H "Accept: application/json" -u "${clientId}:${clientSecret}" --output "${http_output_file}" "${oauth_host}/oauth/token?grant_type=client_credentials")

	if [ $HTTP_STATUS -eq 200  ]; then
  		logger ${log_opts} "Obtained access_token successfully"
  		token=$(jq -r .access_token ${http_output_file})
	else
		message="Error: Could not obtain access_token"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file} || {
				jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" '{errorMessage: $message, httpStatus: $httpStatus}' > ${output_file}
				}
		return 1
	fi

}

get_hdb_token(){

}

upload_file(){

	fileName=$(basename ${inputFilePath})
	file_request_body=/tmp/file_request_body.json
	jq --null-input {} \
	  | jq --arg fileType ${filetype} '.type=$fileType' \
	  | jq --arg fileName ${fileName} '.metadata.originalFileName=$fileName' > ${file_request_body}

	get_user_info
	post_file 1
	get_signed_url 1
	update_file_status "UPLOADING" 1
	upload_file_s3
	update_file_status "UPLOADED" 1
	wait_for_file_complete

}

create_new_report() {
	fileType=$(jq -r .type ${output_s3file})
	if [ "${fileType}" = "VCF" ]; then
		projectType=$(jq -r .type ${request_body})
		projectModel=$(node /opt/js/parse-samples.js ${output_s3file} ${projectType} ${samples_info} | jq -c .)
		projectModelErrors=$(jq -c --null-input --argjson p "${projectModel}" '$p.projectModel.errors')
		if [ "${projectModelErrors}" = "null" ]; then
			HTTP_STATUS=$(jq . ${request_body} \
		  	| jq --arg fileId "${fileId}" '.input.fileId=$fileId' \
		  	| jq --argjson p "${projectModel}" '.parameters |= . + $p.projectModel' \
		  	| curl ${curl_opts} --write-out "%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" -d @- "${host}/${version}/analysisRequests")
		else
			logger ${log_opts} "${projectModelErrors}. For details, see ${output_file}. Exiting..."
			jq --null-input --slurpfile fileResponse ${output_s3file} --argjson p "${projectModel}" '{
				input: { fileId:$fileResponse[0].id },
				output: {
					fileCheck: {
						id:$fileResponse[0].id,
						originalFileName:$fileResponse[0].originalFileName,
						status:$fileResponse[0].status,
						statusMessages:$fileResponse[0].statusMessages
					},
					report: $p.projectModel
				},
				status:"ERROR"
			}' >> ${output_file} || {logger ${log_opts} http status: ${HTTP_STATUS}}
			exit 1
		fi
	else
		HTTP_STATUS=$(jq . ${request_body} \
		  | jq --arg fileId "${fileId}" '.input.fileId=$fileId' \
		  | curl ${curl_opts} --write-out "%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" -d @- "${host}/${version}/analysisRequests")
	fi
	error=$(jq -r .error ${http_output_file})
	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		logger ${log_opts} "POST-ed successfully to ${host}/${version}/analysisRequests"
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_access_token

		logger ${log_opts} "Token refreshed. Re-attempting to create new report. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
		retry_count=$((retry_count + 1))
		create_new_report "$retry_count"
	else
		message="Error: Failed to contact ${host}/${version}/analysisRequests"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}
		exit 1
	fi
}

check_status(){
	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" -X GET -H "Accept: application/json" -H "Authorization: bearer ${token}" --output "${http_output_file}" ${host}/${version}/analysisRequests/${analysisRequestId})
	error=$(jq -r .error ${http_output_file})
	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		status=$(jq -r .status ${http_output_file})
		logger ${log_opts} "Status is $status"
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_access_token

		logger ${log_opts} "Token refreshed. Re-checking status..."
		retry_count=$((retry_count + 1))
		check_status "$retry_count"
	else
		message="Error: Failed to get status of analysisRequest ${host}/${version}/analysisRequests/${analysisRequestId}"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file} || {logger ${log_opts} http status: ${HTTP_STATUS}}
		exit 1
	fi
}


wait_for_file_complete(){

	fileStatus=""
	while [ "$fileStatus" != "COMPLETED" ]
	do
		logger ${log_opts} "Checking file status ...."
		check_file_status 0
		sleep 10
	done
	cp ${http_output_file} ${output_s3file}
}

check_file_status(){

	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" -X GET -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" "${host}/files/${fileId}")
	error=$(jq -r .error ${http_output_file})
	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		fileStatus=$(jq -r .status ${http_output_file})
		logger ${log_opts} "FileStatus is $fileStatus"

		if [ "$fileStatus" == "TIMEOUT" ] || [ "$fileStatus" == "ERROR" ]; then
			message="Error: file status error or timeout"
			logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
			jq --null-input --slurpfile httpResponse ${http_output_file} '{
				input: { fileId:$httpResponse[0].id },
				output: {
					fileCheck: {
						id:$httpResponse[0].id,
						originalFileName:$httpResponse[0].originalFileName,
						status:$httpResponse[0].status,
						statusMessages:$httpResponse[0].statusMessages
					},
					report: {
						statusMessage:"we were unable to create the report. The file is invalid"
					}
				},
				status:"ERROR"
			}' >> ${output_file} || {logger ${log_opts} http status: ${HTTP_STATUS}}
			exit 1
		fi
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_access_token

		logger ${log_opts} "Token refreshed. Re-checking file status..."
		retry_count=$((retry_count + 1))
		check_status "$retry_count"
	else
		message="Error: Failed to get file status"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file} || {logger ${log_opts} http status: ${HTTP_STATUS}}
		exit 1
	fi
}


get_user_info(){
	logger ${log_opts} "Getting user info..."
	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" -X GET -H "Accept: application/json" -H "Authorization: bearer ${token}" --output "${http_output_file}" "${oauth_host}/users/info")

	if [ $HTTP_STATUS -eq 200  ]; then
  		logger ${log_opts} "Obtained user info successfully"
  		userId=$(jq -r .id ${http_output_file})
	else
		message="Error: Could not obtain user info"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file} || {
				jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" '{errorMessage: $message, httpStatus: $httpStatus}' > ${output_file}
				}
		return 1
	fi
}

post_file(){

	logger ${log_opts} "Posting file... "
	HTTP_STATUS=$(jq . ${file_request_body} \
	  | jq --arg ownerId "${userId}" '.ownerId=$ownerId' \
	  | curl ${curl_opts} --write-out "%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" -d @- "${host}/files")
	error=$(jq -r .error ${http_output_file})
	local retry_count=$1

	fileId=$(jq -r .id ${http_output_file})
	if [ ! $HTTP_STATUS -eq 201  ] || [ "${fileId}" = "null" ]
	then
		error=$(jq -r .error ${http_output_file})
		exception=$(jq -r .exception ${http_output_file})
		local retry_count=$1

		if [ $HTTP_STATUS -eq 401 ] && [ "$error" = "invalid_token" ] && [ ! $retry_count -eq $max_retry_count ]; then
			logger ${log_opts} "Token expired. Refreshing..."
			get_access_token

			logger ${log_opts} "Token refreshed. Re-attempting to post file. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
			retry_count=$((retry_count + 1))
			post_file "$retry_count"
		else
			message="Error: Could not post file"
			logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
			jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}
			exit 1
		fi
	fi

}

update_file_status(){

	logger ${log_opts} "Updating file status... "
	HTTP_STATUS=$(jq --null-input {} \
	  | jq --arg status "$1" '.status=$status' \
	  | curl ${curl_opts} --write-out "%{http_code}" -X PATCH -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" -d @- "${host}/files/${fileId}")
	error=$(jq -r .error ${http_output_file})
	local retry_count=$2

	fileId=$(jq -r .id ${http_output_file})
	if [ ! $HTTP_STATUS -eq 200  ] || [ "${fileId}" = "null" ]
	then
		error=$(jq -r .error ${http_output_file})
		exception=$(jq -r .exception ${http_output_file})
		local retry_count=$2

		if [ $HTTP_STATUS -eq 401 ] && [ "$error" = "invalid_token" ] && [ ! $retry_count -eq $max_retry_count ]; then
			logger ${log_opts} "Token expired. Refreshing..."
			get_access_token

			logger ${log_opts} "Token refreshed. Re-attempting to update file status. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
			retry_count=$((retry_count + 1))
			post_file "$retry_count"
		else
			message="Error: Could not update file status"
			logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
			jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}
			exit 1
		fi
	fi

}

get_signed_url(){

	logger ${log_opts} "Getting url... "
	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" -X POST -H "X-AB-id: ${fileId}" -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" --output "${http_output_file}" "${host}/s3/v4Sign?v4=true&client=api")
	error=$(jq -r .error ${http_output_file})
	local retry_count=$1

	signedUrl=$(jq -r .preSignedUrl ${http_output_file})
	if [ ! $HTTP_STATUS -eq 201  ]
	then
		error=$(jq -r .error ${http_output_file})
		exception=$(jq -r .exception ${http_output_file})
		local retry_count=$1

		if [ $HTTP_STATUS -eq 401 ] && [ "$error" = "invalid_token" ] && [ ! $retry_count -eq $max_retry_count ]; then
			logger ${log_opts} "Token expired. Refreshing..."
			get_access_token

			logger ${log_opts} "Token refreshed. Re-attempting to get signed url. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
			retry_count=$((retry_count + 1))
			get_signed_url "$retry_count"
		else
			message="Error: Could not get signed url"
			logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
			jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}
			update_file_status "ERROR" 1
			exit 1
		fi
	fi
}

upload_file_s3(){
	logger ${log_opts} "Uploading file to s3... "
	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" --upload-file ${inputFilePath}  -H "x-amz-server-side-encryption: ${sseOption}" --output "${http_output_file}" "${signedUrl}")

	if [ ! $HTTP_STATUS -eq 200  ]
	then
		responseCode=$(xmllint --xpath "string(//Code)" ${http_output_file})
		responseMessage=$(xmllint --xpath "string(//Message)" ${http_output_file})
		message="Error: Could not upload the file"
		logger ${log_opts} "${message}. For details, see ${output_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --arg responseMessage "${responseMessage}" --arg responseCode "${responseCode}" '{errorMessage: $message, httpStatus: $httpStatus, responseCode: $responseCode, responseMessage: $responseMessage}'  >> ${output_file}
		update_file_status "ERROR" 1
		exit 1
	fi

}

get_report_summary() {
	HTTP_STATUS=$(curl ${curl_opts} --write-out "%{http_code}" -X GET -H "Accept: application/json" -H "Authorization: bearer ${token}" --output "${http_output_file}" ${host}/${version}/analysisRequests/${analysisRequestId}/summary)

	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		cat ${http_output_file} > ${summary_file}
		logger ${log_opts} "Summary obtain succesfully"
		logger ${log_opts} "Summary file written to ${summary_file}"
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_access_token

		logger ${log_opts} "Token refreshed. Re-checking status..."
		retry_count=$((retry_count + 1))
		get_summary "$retry_count"
	else
		error=$(jq -r .error ${http_output_file})
		message="Error: Failed to get summary of analysisRequest ${host}/${version}/analysisRequests/${analysisRequestId}/summary"
		logger ${log_opts} "${message}. For details, see ${summary_file}. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${summary_file} || {logger ${log_opts} http status: ${HTTP_STATUS}}
		exit 1
	fi
}


share_report(){

	logger ${log_opts} "Sharing the report... "
	shareRequestBody=$(jq -c --null-input --arg email "${shareEmail}" '[{ email: $email, allowedToShare: true }]')

	HTTP_STATUS=$(curl --retry 1 --retry-delay 30 --retry-max-time 300 --write-out "%{http_code}" -X POST -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: bearer ${token}" -H "Cache-Control: no-cache" -d "${shareRequestBody}" --output "${http_output_file}" ${host}/${version}/analysisRequests/${analysisRequestId}/shares)

	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		logger ${log_opts} "Report shared succesfully"
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_access_token

		logger ${log_opts} "Token refreshed. Re-attempting to share report. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
		retry_count=$((retry_count + 1))
		share_report "$retry_count"
	else
		error=$(jq -r .error ${http_output_file})
		message="Error: Failed to share the report ${host}/${version}/analysisRequests/${analysisRequestId}/share"
		logger ${log_opts} "${message}. For details, see ${output_file}_share_error.json. Exiting..."
		jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}_share_error.json || {logger ${log_opts} http status: ${HTTP_STATUS}}
		exit 1
	fi

}

post_to_discussion(){
	#hit internal API endpoint servicename:3001/api/advaita/report
	logger ${log_opts} "Posting the output report to the HumanDB message board ..."
	discussionRequestBody=$(jq -c --null-input --arg outputFile "${output_file}" --arg title "${title}" '[{ title: $title, outputFile: $outputFile }]')
	HTTP_STATUS=$(curl --retry 1 --retry-delay 30 --retry-max-time 300 --write-out "%{http_code}"\\)

	local retry_count=$1

	if [ $HTTP_STATUS -eq 200  ]; then
		logger ${log_opts} "Report posted to HumanDB message board successfully ..."
	elif [ $HTTP_STATUS -eq 401 ] && [[ "$error" = "invalid_token" ]] && [ ! $retry_count -eq $max_retry_count ]; then
		logger ${log_opts} "Token expired. Refreshing..."
		get_hdb_token

		logger ${log_opts} "Token refreshed. Re-attempting to share report. Retry-Count=$retry_count. Max-Retry-Count=$max_retry_count ..."
		retry_count=$((retry_count + 1))
		post_to_discussion "$retry_count"
	###
else
	error=$(jq -r .error ${http_output_file})
	message="Error: Failed to post the report ${host}/${version}/analysisRequests/${analysisRequestId}/share"
	logger ${log_opts} "${message}. For details, see ${output_file}_share_error.json. Exiting..."
	#jq --null-input --arg message "${message}" --arg httpStatus "${HTTP_STATUS}" --slurpfile httpResponse ${http_output_file} '{errorMessage: $message, httpStatus: $httpStatus, httpResponse: $httpResponse}'  >> ${output_file}_share_error.json || {logger ${log_opts} http status: ${HTTP_STATUS}}
	exit 1
fi

}
