import 'package:flutter/material.dart';
import 'package:thclab_signing_plugin/thclab_signing_plugin.dart';

void main() async{
  WidgetsFlutterBinding.ensureInitialized();
  var signer = await ThclabSigningPlugin.establishForEd25519();
  runApp(MyApp(signer: signer,));
}

class MyApp extends StatefulWidget {
  final signer;
  const MyApp({Key? key, this.signer}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  TextEditingController writeKeyController = TextEditingController();
  TextEditingController writeDataController = TextEditingController();
  TextEditingController readKeyController = TextEditingController();
  TextEditingController deleteKeyController = TextEditingController();
  TextEditingController editKeyController = TextEditingController();
  TextEditingController editDataController = TextEditingController();
  TextEditingController signDataController = TextEditingController();
  String writeResult = '';
  String readResult = '';
  String deleteResult = '';
  String editResult = '';
  String currentKey = '';
  String nextKey = '';
  String signature = '';
  late var signer;

  @override
  void initState(){
    signer = widget.signer;
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('storage example app'),
        ),
        body: SingleChildScrollView(
          child: Center(
              child: Column(
                children: [
                  const Text(
                    'Signer uuid:',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  Text(signer.uuid),
                  const Divider(),
                  const Text(
                    'Current keys:',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      currentKey = await signer.getCurrentPubKey();
                      nextKey = await signer.getNextPubKey();
                      setState(() {

                      });
                    },
                    child: const Text('Get keys!'),
                  ),
                  Text(currentKey),
                  Text(nextKey),
                  const Divider(),
                  const Text(
                    'Rotate keys:',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      await signer.rotateForEd25519();
                      currentKey = await signer.getCurrentPubKey();
                      nextKey = await signer.getNextPubKey();
                      setState(() {

                      });
                    },
                    child: const Text('Rotate!'),
                  ),
                  const Divider(),
                  const Text(
                    'Sign data:',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  TextFormField(
                    controller: signDataController,
                    decoration: const InputDecoration(hintText: "data"),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      signature = await signer.sign(signDataController.text);
                      setState(() {

                      });
                    },
                    child: const Text('Sign!'),
                  ),
                  Text(signature),
                  const Divider(),
                  const Text(
                    'Clean up:',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      await ThclabSigningPlugin.cleanUp(signer);
                      setState(() {
                        currentKey = '';
                        nextKey = '';
                        signature = '';
                      });
                    },
                    child: const Text('Clean up!'),
                  ),
                  const Divider(
                    thickness: 5,
                  ),
                  const Text(
                    '1. Write',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  TextFormField(
                    controller: writeKeyController,
                    decoration: const InputDecoration(hintText: "key"),
                  ),
                  TextFormField(
                    controller: writeDataController,
                    decoration: const InputDecoration(hintText: "data"),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      if (writeDataController.text.isNotEmpty &&
                          writeKeyController.text.isNotEmpty) {
                        var result = await ThclabSigningPlugin.writeData(
                            writeKeyController.text, writeDataController.text);
                        if (result == true) {
                          setState(() {
                            writeResult = 'Success!';
                          });
                        } else {
                          setState(() {
                            writeResult = 'Failure!';
                          });
                        }
                      }
                    },
                    child: const Text('Write!'),
                  ),
                  Text(writeResult),
                  const Divider(),
                  const Text(
                    '2. Read',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  TextFormField(
                    controller: readKeyController,
                    decoration: const InputDecoration(hintText: "key"),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      if (readKeyController.text.isNotEmpty) {
                        var result = await ThclabSigningPlugin.readData(
                            readKeyController.text);
                        if (result != false) {
                          setState(() {
                            readResult = result;
                          });
                        } else {
                          setState(() {
                            readResult = 'Failure!';
                          });
                        }
                      }
                    },
                    child: const Text('Read!'),
                  ),
                  Text(readResult),
                  const Divider(),
                  const Text(
                    '3. Delete',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  TextFormField(
                    controller: deleteKeyController,
                    decoration: const InputDecoration(hintText: "key"),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      if (deleteKeyController.text.isNotEmpty) {
                        var result = await ThclabSigningPlugin.deleteData(
                            deleteKeyController.text);
                        if (result == true) {
                          setState(() {
                            deleteResult = "Deleted!";
                          });
                        } else {
                          setState(() {
                            deleteResult = "Failure!";
                          });
                        }
                      }
                    },
                    child: const Text('Delete!'),
                  ),
                  Text(deleteResult),
                  const Divider(),
                  const Text(
                    '4. Edit',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
                  ),
                  TextFormField(
                    controller: editKeyController,
                    decoration: const InputDecoration(hintText: "key"),
                  ),
                  TextFormField(
                    controller: editDataController,
                    decoration: const InputDecoration(hintText: "data"),
                  ),
                  RawMaterialButton(
                    onPressed: () async {
                      if (editDataController.text.isNotEmpty &&
                          editKeyController.text.isNotEmpty) {
                        var result = await ThclabSigningPlugin.editData(
                            editKeyController.text, editDataController.text);
                        if (result == true) {
                          setState(() {
                            editResult = 'Success!';
                          });
                        } else {
                          setState(() {
                            editResult = 'Failure!';
                          });
                        }
                      }
                    },
                    child: const Text('Edit!'),
                  ),
                  Text(editResult),
                  const Divider(),

                ],
              )),
        ),
      ),
    );
  }
}