package edu.buffalo.cse.cse486586.simpledht;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.CursorIndexOutOfBoundsException;
import android.database.MatrixCursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

public class SimpleDhtProvider extends ContentProvider {

    private static final String TAG = "SimpleDhtProvider";
    private static final String TABLE_NAME = "MESSAGES";
    private static final String TYPE_KEY = "type";
    private static final String ID_KEY = "id";
    private static final String PORT_KEY = "port";
    private static final String PRED_KEY = "pred";
    private static final String SUCC_KEY = "succ";
    private static final String PRED_PORT_KEY = "predPort";
    private static final String SUCC_PORT_KEY = "succPort";
    private static final String CHECKED_KEY = "checked";
    private static final String CENTRAL_PORT = "11108";
    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";
    private static final String RESULTS_FIELD = "results";
    private static final int SERVER_PORT = 10000;
    private String serverPortHash;
    private String myPort;
    private String predId = null;
    private String succId = null;
    private String predPort = null;
    private String succPort = null;
    private static final ArrayList<String> nodeList = new ArrayList<String>();
    private static final HashMap<String, String> hashPortMap = new HashMap<String, String>();
    private DBHelper dBHelper;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO delete
        Log.e("DELETE", selection);
        HashMap<String, String> msgMap = new HashMap<String, String>();
        String resp = null;

        Integer rowId = 0;
        SQLiteDatabase sqLiteDatabase = dBHelper.getReadableDatabase();

        // if @ or query then perform on local else propogate to successor
        if(selection.equals("@")){
            rowId = sqLiteDatabase.delete(TABLE_NAME, "1", null);
            if(rowId > 0){
                Log.e("DELETED",String.valueOf(rowId) + " rows");
            }
        }
        else if(selection.contains("DELETE")){
            String[] res = selection.split(" &&&&& ");

            selection = res[1];
            String keyHash = "";
            try{
                keyHash = genHash(selection);
            }
            catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
            if(!keyHash.equals("")){
                String[] actualSelectionArgs = {selection};
                rowId = sqLiteDatabase.delete(TABLE_NAME,"key=?",actualSelectionArgs);
            }

        }
        //else propogate to successor
        else{
            msgMap.put(TYPE_KEY,"DELETE");
            msgMap.put(ID_KEY, selection);
            msgMap.put(PORT_KEY, myPort);
            try {
                resp = new ClientTask().execute(getJSON(msgMap), myPort).get();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        // return response
        if(resp == null)
            return rowId;
        return Integer.parseInt(resp);
    }

    @Override
    public String getType(Uri uri) {
        // TODO getType
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO insert
        String keyHash = null;
        HashMap<String, String > msgMap = new HashMap<String, String>();
        if (values.containsKey(KEY_FIELD) && values.containsKey(VALUE_FIELD)){

            try{
                keyHash = genHash(values.getAsString(KEY_FIELD));
                values.put("hash",keyHash);
            }catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
            // insert in local if no other avd present or value belongs to the region
            if(succId == null || values.containsKey("FORCED")){
                SQLiteDatabase database = dBHelper.getWritableDatabase();
                ContentValues insValues = new ContentValues();
                insValues.put(KEY_FIELD, values.getAsString(KEY_FIELD));
                insValues.put(VALUE_FIELD, values.getAsString(VALUE_FIELD));
                long rowId;
                try{
                    rowId = database.insertOrThrow(TABLE_NAME, null, insValues);
                }
                catch (SQLiteException exception){
                    String[] args = {values.getAsString(KEY_FIELD)};
                    rowId = database.update(TABLE_NAME,insValues,"key = ?",args);
                }

                if (rowId > 0) {
                    return uri;
                }
            }
            // else propogate to successor
            else{
                msgMap.put(TYPE_KEY,"INSERT");
                msgMap.put(KEY_FIELD, values.getAsString(KEY_FIELD));
                msgMap.put(VALUE_FIELD, values.getAsString(VALUE_FIELD));
                if(!values.containsKey(PORT_KEY))
                    msgMap.put(PORT_KEY, myPort);
                else
                    msgMap.put(PORT_KEY, values.getAsString(PORT_KEY));

                if (keyHash != null && (succPort.equals(values.getAsString(PORT_KEY)) ||
                        (keyHash.compareTo(serverPortHash) > 0 && keyHash.compareTo(succId) <= 0 ||
                                (succId.compareTo(serverPortHash) < 0 &&
                                        (keyHash.compareTo(serverPortHash) >= 0 ||
                                                keyHash.compareTo(succId) <= 0))))) {
                    msgMap.put("FORCED", "TRUE");
                }
                try {
                    new ClientTask().execute(getJSON(msgMap), succPort).get();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }


            }

        }
        return null;
    }

    @Override
    public boolean onCreate() {
        // TODO onCreate
        // start dbHelper and serversocket
        dBHelper = new DBHelper(getContext());


        TelephonyManager tel = (TelephonyManager)getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        String resp = null;


        try{
            ServerSocket socket = new ServerSocket(SERVER_PORT);
            socket.setReuseAddress(true);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, socket);
        }catch (IOException e){
            e.printStackTrace();
        }

        try {

            serverPortHash = genHash(portStr);
            Log.e(TAG, portStr);
            Log.e(TAG, serverPortHash);

            // if not central port then issue a join requests
            if(!portStr.equals("5554")){
                Thread.sleep(2000);
                HashMap<String, String > mapToSend = new HashMap<String, String>();
                mapToSend.put(TYPE_KEY, "JOIN");
                mapToSend.put(ID_KEY, serverPortHash);
                mapToSend.put(PORT_KEY, myPort);
                String checked = CENTRAL_PORT;
                mapToSend.put(CHECKED_KEY, checked);
                resp = new ClientTask().execute(getJSON(mapToSend),CENTRAL_PORT).get();
                if(!resp.equals("")){
                    HashMap<String, String> msgMap = getMap(resp);
                    succId = msgMap.get(SUCC_KEY);
                    succPort = msgMap.get(SUCC_PORT_KEY);
                    predId = msgMap.get(PRED_KEY);
                    predPort = msgMap.get(PRED_PORT_KEY);
                    msgMap.put(TYPE_KEY, "PRED UPDATE");
                    // send updates to the predecessor and successor
                    new ClientTask().execute(getJSON(msgMap), succPort).get();
                    msgMap.put(TYPE_KEY, "SUCC UPDATE");
                    new ClientTask().execute(getJSON(msgMap), predPort).get();
                }

            }
            else{
                //if central port then mantain a circular list
                nodeList.add(serverPortHash);
                hashPortMap.put(serverPortHash, myPort);
            }

        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage());
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }


        // If you need to perform any one-time initialization new task, please do it here.
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO query
        String[] columnNames = {"key", "value"};
        MatrixCursor matrixCursor = new MatrixCursor(columnNames);
        HashMap<String, String> msgMap = new HashMap<String, String>();
        String resp = null;

        Cursor cursor = null;
        SQLiteDatabase sqLiteDatabase = dBHelper.getReadableDatabase();

        //if query is not * then perform on local
        if(selection.equals("@")){
            cursor = sqLiteDatabase.rawQuery("SELECT * FROM " + TABLE_NAME, null);
        }
        else if(selection.contains("QUERY")){
            String[] res = selection.split(" &&&&& ");

            selection = res[1];
            String keyHash = "";
            try{
                keyHash = genHash(selection);
            }
            catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
            if(!keyHash.equals("")){
                String[] actualSelectionArgs = {selection};
                cursor = sqLiteDatabase.query(TABLE_NAME, columnNames, "key= ?", actualSelectionArgs,
                        null, null, null);
            }

        }
        // else propogate to successor
        else{
            msgMap.put(TYPE_KEY,"QUERY");
            msgMap.put(ID_KEY, selection);
            msgMap.put(CHECKED_KEY, myPort);
            msgMap.put(PORT_KEY, myPort);
            try {
                resp = new ClientTask().execute(getJSON(msgMap), myPort).get();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }

        // get local response
        if( cursor != null && cursor.getColumnCount() == 2){
            if(cursor.moveToFirst()){
                do{
                    int keyColValue = cursor.getColumnIndex("key");
                    int valueColValue = cursor.getColumnIndex("value");
                    String key = null;
                    String value = null;
                    try{
                        key = cursor.getString(keyColValue);
                        value = cursor.getString(valueColValue);

                    }
                    catch (CursorIndexOutOfBoundsException exception){
                        Log.e(TAG,selection);
                        Log.e(TAG,selection.getClass().toString());
                    }
                    Object[] columnValues = {key, value};
                    matrixCursor.addRow(columnValues);
                }
                while (cursor.moveToNext());

            }

        }
        //get response from successor if any
        if(resp != null && !resp.equals("")){
            HashMap<String, String> results = getMap(getMap(resp).get(RESULTS_FIELD));
            for(String key : results.keySet()){
                Object[] columnValues = {key, results.get(key)};
                matrixCursor.addRow(columnValues);
            }
        }
        //if cursor got some rows then return
        if(matrixCursor.getCount() > 0){
            return matrixCursor;
        }

        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO update
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private class ClientTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... msgs) {
            String message = msgs[0];
            String remotePort = msgs[1];
            Socket socket = null;
            String receivedMessage = "";
            try {
                socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(remotePort));
                OutputStream sendStream = socket.getOutputStream();
                DataOutputStream sendData = new DataOutputStream(sendStream);
                sendData.writeUTF(message);
                sendData.flush();
                DataInputStream recvData = new DataInputStream(socket.getInputStream());
                receivedMessage = recvData.readUTF();
            } catch (IOException e) {
                //e.printStackTrace();
            }
            return receivedMessage;
        }
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            Socket socket;

            Uri.Builder uriBuilder = new Uri.Builder();
            uriBuilder.authority("edu.buffalo.cse.cse486586.simpledht.provider");
            uriBuilder.scheme("content");
            Uri mUri = uriBuilder.build();


            while(true) {

                try{
                    socket = serverSocket.accept();
                    DataInputStream receivedStream = new DataInputStream(socket.getInputStream());
                    String receivedMessage = receivedStream.readUTF();
                    DataOutputStream sendData = new DataOutputStream(socket.getOutputStream());

                    HashMap<String, String> msgMap = getMap(receivedMessage);
                    String id = msgMap.get(ID_KEY);
                    String port = msgMap.get(PORT_KEY);

                    if(msgMap.get(TYPE_KEY).equals("JOIN")){
                        //if join request then get neighbours from circular list and respond
                        nodeList.add(id);
                        Collections.sort(nodeList);
                        hashPortMap.put(id,port);
                        if(succId == null) {
                            //if no other node present then both successor and predecessor will be
                            // this node
                            succId = id;
                            succPort = msgMap.get(PORT_KEY);
                            predId = id;
                            predPort = msgMap.get(PORT_KEY);
                            msgMap.put(PRED_KEY, serverPortHash);
                            msgMap.put(SUCC_KEY, serverPortHash);
                            msgMap.put(PRED_PORT_KEY, myPort);
                            msgMap.put(SUCC_PORT_KEY, myPort);
                            msgMap.put(TYPE_KEY, "BOTH");
                            sendData.writeUTF(getJSON(msgMap));
                        }
                        else{
                            // get neighbours for the node and respond
                            Integer nodePos = nodeList.indexOf(id);

                            Integer predPos = nodePos == 0 ? nodeList.size() - 1 : nodePos - 1;
                            Integer succPos = nodePos == nodeList.size() - 1 ? 0 : nodePos + 1;
                            msgMap.put(PRED_KEY, nodeList.get(predPos));
                            msgMap.put(PRED_PORT_KEY, hashPortMap.get(nodeList.get(predPos)));
                            msgMap.put(SUCC_KEY, nodeList.get(succPos));
                            msgMap.put(SUCC_PORT_KEY, hashPortMap.get(nodeList.get(succPos)));
                            sendData.writeUTF(getJSON(msgMap));
                        }

                    }
                    else if(msgMap.get(TYPE_KEY).equals("PRED UPDATE")){
                        //update predecessor
                        predId = id;
                        predPort = port;
                        sendData.writeUTF("OK");
                    }
                    else if(msgMap.get(TYPE_KEY).equals("SUCC UPDATE")){
                        //update successor
                        succId = id;
                        succPort = port;
                        sendData.writeUTF("OK");
                    }
                    else if(msgMap.get(TYPE_KEY).equals("QUERY")){
                        String selection = id;
                        HashMap<String, String> resultsMap = new HashMap<String, String>();
                        if(succPort != null && !succPort.equals(port)){
                            //if successor present and has not been processed then forward request
                            socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(succPort));
                            OutputStream sendStream = socket.getOutputStream();
                            DataOutputStream sendSuccData = new DataOutputStream(sendStream);
                            sendSuccData.writeUTF(receivedMessage);
                            receivedMessage = new DataInputStream(socket.getInputStream()).readUTF();
                            resultsMap = getMap(getMap(receivedMessage).get(RESULTS_FIELD));
                        }
                        //get results from local
                        selection = selection.equals("*") ? "@" : "QUERY &&&&& " + selection;
                        Cursor cursor = query(mUri, null, selection, null, null);
                        //append to retrieved result from successor and send back
                        msgMap.put(RESULTS_FIELD, convertCursorToString(cursor, resultsMap));
                        sendData.writeUTF(getJSON(msgMap));
                    }
                    else if(msgMap.get(TYPE_KEY).equals("INSERT")){
                        //call insert
                        ContentValues values = new ContentValues();
                        for(String key : msgMap.keySet()){
                            values.put(key, msgMap.get(key));
                        }
                        insert(mUri, values);
                    }
                    else if(msgMap.get(TYPE_KEY).equals("DELETE")){
                        String selection = id;
                        if(succPort != null && !succPort.equals(port)){
                            //if successor present and has not been processed then forward request
                            socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(succPort));
                            OutputStream sendStream = socket.getOutputStream();
                            DataOutputStream sendSuccData = new DataOutputStream(sendStream);
                            sendSuccData.writeUTF(receivedMessage);
                        }
                        //get results from local
                        selection = selection.equals("*") ? "@" : "DELETE &&&&& " + selection;
                        //append to retrieved result from successor and send back
                        int row = delete(mUri, selection, null);
                        sendData.writeUTF(String.valueOf(row));
                    }

                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    break;
                }
            }
            return null;
        }

    }


    public String convertCursorToString(Cursor resultCursor, HashMap<String,String> resultMap){
        //convert cursor object to json string to be sent on network
        if (resultCursor == null) {
            Log.e(TAG, "Result null");

        }
        if(resultCursor != null && resultCursor.getCount() > 0){
            int keyIndex = resultCursor.getColumnIndex(KEY_FIELD);
            int valueIndex = resultCursor.getColumnIndex(VALUE_FIELD);
            if (keyIndex == -1 || valueIndex == -1) {
                Log.e("convertCursorToString", "Wrong columns");
            }

            else if(resultCursor.moveToFirst()){
                do{
                    keyIndex = resultCursor.getColumnIndex(KEY_FIELD);
                    valueIndex = resultCursor.getColumnIndex(VALUE_FIELD);
                    String returnKey = resultCursor.getString(keyIndex);
                    String returnValue = resultCursor.getString(valueIndex);
                    resultMap.put(returnKey, returnValue);
                }
                while (resultCursor.moveToNext());
            }
        }
        return new JSONObject(resultMap).toString();
    }

    public HashMap<String, String> getMap(String jsonString){
        //convert hashmap to json string to be sent on network
        HashMap<String, String> map = new HashMap<String, String>();
        try{
            JSONObject jObject = new JSONObject(jsonString);
            Iterator<String> keys = jObject.keys();

            while( keys.hasNext() ){
                String key = (String)keys.next();
                String value = jObject.getString(key);
                map.put(key, value);

            }
        }
        catch (JSONException e){
            e.printStackTrace();
        }

        return map;

    }

    public String getJSON(HashMap<String, String> jsonMap){
        //convert json string to hashmap t
        JSONObject json = new JSONObject(jsonMap);
        return json.toString();
    }
}
